Introduction into FauST2
========================

FauST2 stands for Friedrich-Alexander-University Security Tool 2.0 and is a tool for managing, generating and distributing Cisco Access Control Lists (ACLs). It is written entirely in python and has the following features:
 * Full IPv6 and IPv4 support
 * Easy maintainability of ACLs ('nicer' syntax, than cisco's)
 * Robust distribution to routers
 * Support for large scale networks (dozens of routers and hundreds of VLANs)

It aims at reducing time and errors, but not knowledge required to do so, while managing ACLs.

FauST2 does *not* aim at the following:
 * Internal security, any one having access to FauST2 must also be trusted direct access to the routers
 * End-User created ACLs, the ACLs have to be edited by people who could also do it without FauST2

