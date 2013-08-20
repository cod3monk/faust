#!/usr/bin/python

'''An extension to ipaddr.py by Google Inc. to support non-standard, but 
intuitive ip notations

This library extension aims to support the following ip notations:
IPv4:
 * , Notation (127.0.0.1,6 -> includes 127.0.0.1 and 127.0.0.6)
 * - Notation (172.0.0.1-3 -> includes 172.0.0.1, 172.0.0.2 and 172.0.0.3)
 * * Notation (131.0.0.* -> equals to 131.0.0.0-254)
'''

from third_party import ipaddr
from third_party.ipaddr import AddressValueError as AddressValueError
from third_party.ipaddr import NetmaskValueError as NetmaskValueError

any_ = [ipaddr.IPv4Network('0.0.0.0/0'), ipaddr.IPv6Network('::1/0')]

def IPv4Descriptor(desc):
    """Take an IP or Network or Range and returns appropriate lists.

    Args:
        desc: A String, that describes one or more IPv4 ranges, 
            addresses or networks

    Returns:
        A list of IPv4Network objects.

    Raises:
        ValueError: if the string could not be parsed

    """
    iplist = []
    
    for addrblock in desc.split(';'):
        # Try to use ipaddr to parse standard conform notations:
        try:
            iplist.append(ipaddr.IPv4Address(addrblock))
            continue
        except (AddressValueError, NetmaskValueError):
            pass

        try:
            iplist.append(ipaddr.IPv4Network(addrblock))
            continue
        except (AddressValueError, NetmaskValueError):
            pass
        
        # Parsing non-standard notations:
        octets = addrblock.split('.')
        lastoct = octets[-1]
        if lastoct == '*':
            iplist.append(ipaddr.IPv4Network('.'.join(octets[:-1])+'.'+'0/24'))
        else:
            for block in lastoct.split(','):
                if '-' in block:
                    start,end = block.split('-')
                    startaddr = ipaddr.IPv4Address('.'.join(octets[:-1])+'.'+start)
                    endaddr = ipaddr.IPv4Address('.'.join(octets[:-1])+'.'+end)
                    
                    iplist += map(ipaddr.IPv4Address, range(int(startaddr),int(endaddr+1)))
                else:
                    iplist.append(ipaddr.IPv4Address('.'.join(octets[:-1])+'.'+block))
        
    return ipaddr.collapse_address_list(iplist)

def IPv6Descriptor(desc):
    """Take an IP or Network or Range and returns appropriate lists.

    Args:
        desc: A String, that describes one or more IPv4 ranges, 
            addresses or networks

    Returns:
        A list of IPv6Network objects.

    Raises:
        ValueError: if the string could not be parsed

    """

    iplist = []
    
    for addrblock in desc.split(';'):
        # Try to use ipaddr to parse standard conform notations:
        try:
            iplist.append(ipaddr.IPv6Address(addrblock))
            continue
        except (AddressValueError, NetmaskValueError):
            pass

        try:
            iplist.append(ipaddr.IPv6Network(addrblock))
            continue
        except (AddressValueError, NetmaskValueError):
            pass
        
        # Parsing non-standard notations:
        octets = addrblock.split(':')
        lastoct = octets[-1]
        for block in lastoct.split(','):
            if '-' in block:
                start,end = block.split('-')
                startaddr = ipaddr.IPv6Address(':'.join(octets[:-1])+':'+start)
                endaddr = ipaddr.IPv6Address(':'.join(octets[:-1])+':'+end)
                
                iplist += map(ipaddr.IPv6Address, range(int(startaddr),int(endaddr+1)))
            else:
                iplist.append(ipaddr.IPv6Address(':'.join(octets[:-1])+':'+block))
    
    return ipaddr.collapse_address_list(iplist)
    
def IPDescriptor(desc):
    if ':' in desc:
        return IPv6Descriptor(desc)
    elif '.' in desc:
        return IPv4Descriptor(desc)
    
    raise AddressValueError("Invalid Adress: %s" % desc)