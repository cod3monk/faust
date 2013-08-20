"""This class extends pexpect.spawn to specialize setting up SSH connections.
This adds methods for login, logout, and expecting the shell prompt.

$Id$
"""

import pexpect
import time
import os
import re

__all__ = ['ExceptionPxscp', 'pxsftp']

# Exception classes used by this module.
class ExceptionPxscp(pexpect.ExceptionPexpect):
    """Raised for pxsftp exceptions.
    """

class TransportError(ExceptionPxscp):
    """Raised for errors from scp."""

def pxscp(src_path, dst_path, src_username=None, src_server=None, dst_username=None, 
        dst_server=None, login_timeout=10, port=None, ssh_key=None, force_password=False, 
        timeout=30, maxread=2000, searchwindowsize=None, logfile=None, cwd=None, env=None, 
        password=''):

        ssh_options = '-q'
        if force_password:
            ssh_options = ssh_options + " -o'RSAAuthentication=no' -o 'PubkeyAuthentication=no'"
        if port is not None:
            ssh_options = ssh_options + ' -p %s'%(str(port))
        if ssh_key is not None:
            try:
                os.path.isfile(ssh_key)
            except:
                raise ExceptionPxscp ('private ssh key does not exist')
            ssh_options = ssh_options + ' -i %s' % (ssh_key)
        else:
            ssh_options += ' -o PubkeyAuthentication=no'
        cmd = "scp %s " % ssh_options
        
        if src_username:
            assert src_server, "src_server is required if src_username is used!"
            cmd += "%s@" % src_username
        if src_server:
            cmd += "%s:" % (src_server)
        cmd += src_path+" "
        
        if dst_username:
            assert dst_server, "dst_server is required if dst_username is used!"
            cmd += "%s@" % dst_username
        if dst_server:
            cmd += "%s:" % dst_server
        cmd += dst_path
        
        # This does not distinguish between a remote server 'password' prompt
        # and a local ssh 'passphrase' prompt (for unlocking a private key).
        px = pexpect.spawn(cmd, timeout=timeout, maxread=maxread, 
            searchwindowsize=searchwindowsize, logfile=logfile, cwd=cwd, 
            env=env)
            
        i = px.expect(["(?i)are you sure you want to continue connecting", 
            "(?i)(?:password)|(?:passphrase for key)", 
            "(?i)permission denied", "(?i)Administratively disabled.", pexpect.TIMEOUT, 
            "(?i)connection closed by remote host", pexpect.EOF], timeout=login_timeout)

        # First phase
        if i==0:
            # New certificate -- always accept it.
            # This is what you get if SSH does not have the remote host's
            # public key stored in the 'known_hosts' cache.
            px.sendline("yes")
            i = px.expect(["(?i)are you sure you want to continue connecting", 
                "(?i)(?:password)|(?:passphrase for key)", 
                "(?i)permission denied", "(?i)Administratively disabled.", 
                "(?i)terminal type", pexpect.EOF, pexpect.TIMEOUT])
        if i==1: # password or passphrase
            px.sendline(password)
            i = px.expect(["(?i)are you sure you want to continue connecting", 
                "(?i)(?:password)|(?:passphrase for key)", 
                "(?i)permission denied", "(?i)Administratively disabled.", 
                "(?i)terminal type", pexpect.EOF, pexpect.TIMEOUT])
        if i==4:
            px.sendline(terminal_type)
            i = px.expect(["(?i)are you sure you want to continue connecting", 
                "(?i)(?:password)|(?:passphrase for key)", 
                "(?i)permission denied", "(?i)Administratively disabled.", 
                "(?i)terminal type", pexpect.EOF, pexpect.TIMEOUT])

        # Second phase
        if i==0:
            # This is weird. This should not happen twice in a row.
            px.close()
            raise ExceptionPxscp ('Weird error. Got "are you sure" prompt twice.')
        elif i==1: # password prompt again
            # For incorrect passwords, some ssh servers will
            # ask for the password again, others return 'denied' right away.
            # If we get the password prompt again then this means
            # we didn't get the password right the first time.
            px.close()
            raise ExceptionPxscp ('password refused')
        elif i==2: # permission denied -- password was bad.
            px.close()
            raise ExceptionPxscp ('permission denied')
        elif i==3: # Administartively disabled
            px.close()
            raise ExceptionPxscp("Administratively disabled")
        elif i==4: # terminal type again? WTF?
            px.close()
            raise ExceptionPxscp ('Weird error. Got "terminal type" prompt twice.')
        elif i==5: # EOF
            if "Error" in px.before:
                return False
            return True
        elif i==6: # Timeout
            #This is tricky... I presume that we are at the command-line prompt.
            #It may be that the shell prompt was so weird that we couldn't match
            #it. Or it may be that we couldn't log in for some other reason. I
            #can't be sure, but it's safe to guess that we did login because if
            #I presume wrong and we are not logged in then this should be caught
            #later when I try to set the shell prompt.
            pass
        elif i==7: # Connection closed by remote host
            px.close()
            raise ExceptionPxscp ('connection closed')
        else: # Unexpected
            px.close()
            raise ExceptionPxscp ('unexpected login response')
        
        return False

if __name__ == '__main__':
    pxscp(src_path='pxscp.py', dst_username='unrza308', dst_server='aladin', 
        dst_path='pxscp.test.py')
    
# vi:ts=4:sw=4:expandtab:ft=python: