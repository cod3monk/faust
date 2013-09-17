=====
FAUST
=====

FAU Security Tool - An ACL generator and distributor.

* Author: Julian Hammer <julian.hammer@u-sys.org>
* License: GPL v3.0

About
=====
FAUST aims at easing the pain which comes with managing many routers and access-control-lists (ACLs) in a big network for both IPv4 and IPv6.
It currently supports only cisco IOS and NXOS devices, ASA support is planned and other platforms could be included in future.

There are two parts to "easing the pain":
    1. Easier writing of ACLs and automatic generation of repeating rule sets.
    2. Automatic distribution to one or more (redundant) routers.

Dependencies
============
- Python 2.6 or higher (not 3.0+)
- pexpect
- openssh

Writing ACLs
============
To simplify and unify writing ACLs for different cisco devices, a new syntax was developed. It supports (unlike IOS devices) CIDR notation, port lists (i.e. "23,80"), IP lists (i.e. "192.168.0.1,254"), pre-defined hosts (i.e. "$rfc1918"), combination of IPv6 and IPv4 in same ACL and rule and much more. The syntax should be intuitive for anybody familiar with cisco ACLs.

Another advancement is the support for auto-generation of typical rule sets, like nagios access to a server. This is accomplished through macros, which may depend on arguments passed from ACL descriptions or NMS information on the according VLAN.

Distribution
============
FAUST uses SSH and SCP to upload the newly generated ACLs to the router. A great deal of work has gone into speed, to allow updating of whole routers at one time, and into security, to assure that there are always valid ACLs bound to the interface. At the moment 57 ACLs are being uploaded in just under 6 minutes.

NMS Integration
===============
The information about VLANs, IP ranges are currently pulled from special text files, examples are included in the repository. The "VLANs" file must contain a description of all VLANs with names, IPv4 ranges and IPv6 ranges. The "TNETs" file contains information about transit networks, which would otherwise not show up in the "VLANs" file.

History and Usage
=================
FAUST is being developed for the regional computing center (RRZE) of the Friedrich-Alexander-University of Erlangen-Nuremberg. It has been in productive use for more then two years on 30+ routers controlling ACLS of over 600 VLANs.

Similar Software
================
"capirca" is a software package by google, which we found to have a too verbose ACL description for our everyday use and it is missing the ACL distribution part.
