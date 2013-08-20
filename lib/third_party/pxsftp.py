"""This class extends pexpect.spawn to specialize setting up SSH connections.
This adds methods for login, logout, and expecting the shell prompt.

$Id$
"""

from pexpect import *
import pexpect
import time
import os
import re

__all__ = ['ExceptionPxsftp', 'pxsftp']

# Exception classes used by this module.
class ExceptionPxsftp(ExceptionPexpect):
    """Raised for pxsftp exceptions.
    """

class TransportError(ExceptionPxsftp):
    """Raised for errors from sftp."""

class pxsftp(spawn):

    """This class extends pexpect.spawn to specialize setting up SFTP
    connections. This adds methods for login, logout, and copying files. 
    It does various tricky things to handle many situations in the SFTP
    login process. For example, if the session is your first login, then 
    pxsftp automatically accepts the remote certificate; or if you have public
    key authentication setup then pxsftp won't wait for the password prompt.

    Example that runs a few commands on a remote server and prints the result::

        import pxsftp
        import getpass
        try:
            s = pxsftp.pxsftp()
            hostname = raw_input('hostname: ')
            username = raw_input('username: ')
            password = getpass.getpass('password: ')
            s.login(hostname, username, password)
            print s.pwd(), s.lpwd()
            print s.lls()
            s.put('foo')  # copy a file
            print s.ls()
            s.get ('foo')
            s.logout()
        except pxsftp.ExceptionPxsftp, e:
            print "pxsftp failed on login."
            print str(e)

    Note that if you have ssh-agent running while doing development with 
    pxsftp then this can lead to a lot of confusion. Many X display managers 
    (xdm, gdm, kdm, etc.) will automatically start a GUI agent. You may see a 
    GUI dialog box popup asking for a password during development. You should 
    turn off any key agents during testing. The 'force_password' attribute 
    will turn off public key authentication. This will only work if the remote
    SSH server is configured to allow password logins. Example of using 
    'force_password' attribute::

            s = pxsftp.pxsftp()
            s.force_password = True
            hostname = raw_input('hostname: ')
            username = raw_input('username: ')
            password = getpass.getpass('password: ')
            s.login(hostname, username, password)
    """

    def __init__(self, timeout=30, maxread=2000, searchwindowsize=None, 
                 logfile=None, cwd=None, env=None):
        spawn.__init__(self, None, timeout=timeout, maxread=maxread, 
            searchwindowsize=searchwindowsize, logfile=logfile, cwd=cwd, 
            env=env)

        self.name = '<pxsftp>'

        # used to match the sftp prompt
        self.PROMPT = r"sftp> "

        self.SSH_OPTS = ""#"-o'RSAAuthentication=no' -o 'PubkeyAuthentication=no'"
        # Disabling X11 forwarding gets rid of the annoying SSH_ASKPASS from
        # displaying a GUI password dialog. I have not figured out how to
        # disable only SSH_ASKPASS without also disabling X11 forwarding.
        # Unsetting SSH_ASKPASS on the remote side doesn't disable it! Annoying!
        #self.SSH_OPTS = "-x -o'RSAAuthentication=no' -o 'PubkeyAuthentication=no'"
        self.force_password = False
        self.auto_prompt_reset = True

    ### TODO: This is getting messy and I'm pretty sure this isn't perfect.
    ### TODO: I need to draw a flow chart for this.
    def login(self,server,username,password='',terminal_type='ansi',login_timeout=10,port=None,ssh_key=None):

        """This logs the user into the given server. If a prompt cannot be 
        found then this will not necessarily cause the login to fail and then
        raises an ExceptionPxssftp exception.
        """

        ssh_options = '-q'
        if self.force_password:
            ssh_options = ssh_options + ' ' + self.SSH_OPTS
        if port is not None:
            ssh_options = ssh_options + ' -p %s'%(str(port))
        if ssh_key is not None:
            try:
                os.path.isfile(ssh_key)
            except:
                raise ExceptionPxsftp ('private ssh key does not exist')
            ssh_options = ssh_options + ' -i %s' % (ssh_key)
        else:
            ssh_options += ' -o PubkeyAuthentication=no'
        cmd = "sftp %s %s@%s" % (ssh_options, username, server)
        
        # This does not distinguish between a remote server 'password' prompt
        # and a local ssh 'passphrase' prompt (for unlocking a private key).
        self._spawn(cmd)
        i = self.expect(["(?i)are you sure you want to continue connecting", 
            "Connected to ", "(?i)(?:password)|(?:passphrase for key)", 
            "(?i)permission denied", "(?i)terminal type", TIMEOUT, 
            "(?i)connection closed by remote host"], timeout=login_timeout)

        # First phase
        if i==0:
            # New certificate -- always accept it.
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            self.sendline("yes")
            i = self.expect(["(?i)are you sure you want to continue connecting", 
                "Connected to ", "(?i)(?:password)|(?:passphrase for key)", 
                "(?i)permission denied", "(?i)terminal type", TIMEOUT])
        if i==2: # password or passphrase
            self.sendline(password)
            i = self.expect(["(?i)are you sure you want to continue connecting", 
            "Connected to ", "(?i)(?:password)|(?:passphrase for key)", 
            "(?i)permission denied", "(?i)terminal type", TIMEOUT])
        if i==4:
            self.sendline(terminal_type)
            i = self.expect(["(?i)are you sure you want to continue connecting", 
            "Connected to ", "(?i)(?:password)|(?:passphrase for key)", 
            "(?i)permission denied", "(?i)terminal type", TIMEOUT])

        # Second phase
        if i==0:
            # This is weird. This should not happen twice in a row.
            self.close()
            raise ExceptionPxsftp ('Weird error. Got "are you sure" prompt twice.')
        elif i==1: # can occur if you have a public key pair set to authenticate.
            ### TODO: May NOT be OK if expect() got tricked and matched a false prompt.
            pass
        elif i==2: # password prompt again
            # For incorrect passwords, some ssh servers will
            # ask for the password again, others return 'denied' right away.
            # If we get the password prompt again then this means
            # we didn't get the password right the first time.
            self.close()
            raise ExceptionPxsftp ('password refused')
        elif i==3: # permission denied -- password was bad.
            self.close()
            raise ExceptionPxsftp ('permission denied')
        elif i==4: # terminal type again? WTF?
            self.close()
            raise ExceptionPxsftp ('Weird error. Got "terminal type" prompt twice.')
        elif i==5: # Timeout
            #This is tricky... I presume that we are at the command-line prompt.
            #It may be that the shell prompt was so weird that we couldn't match
            #it. Or it may be that we couldn't log in for some other reason. I
            #can't be sure, but it's safe to guess that we did login because if
            #I presume wrong and we are not logged in then this should be caught
            #later when I try to set the shell prompt.
            pass
        elif i==6: # Connection closed by remote host
            self.close()
            raise ExceptionPxsftp ('connection closed')
        else: # Unexpected
            self.close()
            raise ExceptionPxsftp ('unexpected login response')
        #print self.before
        #if not self.prompt():
        #    self.close()
        #    raise ExceptionPxsftp ('could not synchronize with original prompt')
        # We appear to be in.
        return True

    def logout(self):
        """This sends exit to the sftp shell."""

        self.sendline("exit")
        self.expect(EOF)
        self.close()

    def prompt(self, timeout=-1):

        """This matches the shell prompt. This is little more than a short-cut
        to the expect() method. This returns True if the shell prompt was
        matched. This returns False if a timeout was raised. 
        Calling prompt() will erase the contents of the 'before' attribute 
        even if no prompt is ever matched. 
        If timeout is not given or it is set to -1 then self.timeout is used.
        """

        if timeout == -1:
            timeout = self.timeout
        i = self.expect([self.PROMPT, TIMEOUT], timeout=timeout)
        if i==1:
            return False
        return True
    
    def get(self, remote, local=None, recursive=False):
        cmd = 'get'
        
        if recursive:
            cmd += ' -r'
        cmd += ' '+remote
        if local:
            cmd += ' '+local
        
        self.sendline(cmd)
        
        # Match "Fetching" line
        self.expect(re.compile(r'Fetching [^ ]+ to [^ ]+\r\n'));
        
        # Fetch possible error or PROMPT
        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         self.PROMPT])
        
        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))

    def pwd(self):
        self.sendline('pwd')
    
        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         r'Remote working directory: ([^\n]+)\r\n'+self.PROMPT]);
        
        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
        else:
            return self.match.group(1)
    
    def lpwd(self):
        self.sendline('lpwd')

        i= self.expect([r'remote ([^\n]+)\r\n',
                        r'local ([^\n]+)\r\n',
                        r'Local working directory: ([^\n]+)\r\n'+self.PROMPT]);

        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
        else:
            return self.match.group(1)
    
    def ls(self):
        self.sendline('ls -1')

        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         r'ls -1\r\n(.+)\r\n'+self.PROMPT]);

        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
        else:
            return self.match.group(1).split('\r\n')
            
    def lls(self):
        self.sendline('lls -1')

        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         r'lls -1\r\n(.+)\r\n'+self.PROMPT]);

        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
        else:
            return self.match.group(1).split('\r\n')
    
    def put(self, local, remote=None, recursive=False):
        cmd = 'put'
        
        if recursive:
            cmd += ' -r'
        cmd += ' '+local
        if remote:
            cmd += ' '+remote
        
        self.sendline(cmd)
        
        # Match "Fetching" line
        i = self.expect([r'Uploading [^ ]+ to [^ ]+\r\n',
                         r'(stat [^\n]+)\r\n']);
        if i==1:
            raise TransportError("Error received: "+self.match.group(1))
        
        # Fetch possible error or PROMPT
        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         self.PROMPT])
        
        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
    
    def rm(self, path):
        cmd = 'rm ' + path
        
        self.sendline(cmd)
        self.expect([r'Removing [^ ]+\r\n'])
        
        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         r'(Couldn\'t [^\n]+)\r\n',
                         self.PROMPT])
        
        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
        elif i==2:
            raise TransportError("Error received: "+self.match.group(1))
    
    def rmdir(self, path):
        cmd = 'rmdir ' + path

        self.sendline(cmd)
        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         r'(Couldn\'t [^\n]+)\r\n',
                         self.PROMPT])

        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))
        elif i==2:
            raise TransportError("Error received: "+self.match.group(1))
        
    def mkdir(self, path):
        cmd = 'mkdir ' + path

        self.sendline(cmd)

        i = self.expect([r'remote ([^\n]+)\r\n',
                         r'local ([^\n]+)\r\n',
                         self.PROMPT])

        if i==0:
            raise TransportError("Remote error received: "+self.match.group(1))
        elif i==1:
            raise TransportError("Local error received: "+self.match.group(1))

if __name__ == '__main__':
    s = pxsftp()
    s.login('testserver', 'testuser', 'testpass')
    try:
        s.get('test.acl')
    except Exception, e:
        print e
    s.get('helper_checker.py','123')
    print s.pwd()
    print s.lpwd()
    assert '123' in s.lls()
    s.put('123')
    assert '123' in s.ls()
    s.rm('123')
    assert '123' not in s.ls()
    try:
        s.rm('foobarbaz')
    except Exception, e:
        print e
    s.mkdir('test123')
    s.rmdir('test123')
    try:
        s.rmdir('test123')
    except Exception, e:
        print e
    
# vi:ts=4:sw=4:expandtab:ft=python: