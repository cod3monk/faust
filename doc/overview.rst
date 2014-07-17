The Overview of FauST2
======================

Definitions
-----------
 * **Policy file** File created by hand, describing IPv4 and IPv6, in- and outbound, rules for one VLAN
 * **VLANs file** File describing all VLANs, with IPv4 and (optionally) IPv6 range, as well as it's routing domain and VLAN id
 * **Aliases file** File containing static aliases, available in all Policy files
 * **MetACL object** Object created from policy files by the parser
 * **ACL string** String containing ACL commands which are valid for execution on cisco routers
 * **Context object** Object describing the environment, where the MetACL object can be applied to
 * **Rule** One ACL command
 * **Macro Call** One reference to a macro, with possible arguments

Process
-------
 1. **Read config**
This is done using :mod:`faust2.lib.config`.
 
Reads the config.ini file, which contains paths to all other configuration files and directories required for proceeding.

 2. **Create Context**
This is done using :class:`faust2.lib.metacl.Context`.

Takes the aliases and VLANs file and creates dictionaries of aliases (separate for v4 and v6) and stores information of the relevant VLAN. All aliases from the file are copied to the dictionary, then the aliases 'any' and 'local' are dynamically set, thus 'any' and 'local' aliases from the aliases file will be overwritten.

 3. **Parse Policy File and generate MetACL Object**
This is done using :func:`faust2.lib.metacl.MetACL.from_context`. 

The policy file is found by its routingdomain and vlan number. The base path of all policies is defined in the config.ini. The policy file has to be in the following path: <base_path_from_config>/<routingdomain>/<vlan_number><extension_from_config>.

The actual parsing is done by :func:`faust2.lib.metacl.MetACL.from_context` getting the filename from the :class:`faust2.lib.metacl.Context` object and then handing the appropriate lines to :func:`faust2.lib.metacl.Rule.from_string` and :func:`faust2.lib.metacl.MacroCall.from_string`. The result of the parsed policy file will be a MetACL object.

The MetACL object (:class:`faust2.lib.metacl.MetACL`) holds all rules (in form of :class:`faust2.lib.metacl.Rule` objects) and Macro Calls (:class:`faust2.lib.metacl.MacroCall`) of one policy file in lists. In and out, as well as v6 and v4 rules are kept in separate lists.

 4. **Generate Cisco ACL String**
This is done using :func:`faust2.lib.cisco.compile`.

All rules held in the MetACL object are converted to cisco acl commands, including pre- and postfix commands for list creation/deletion.

 5. **Transfer to Router**
This is done using :class:`faust2.lib.cisco.Router`, but the logic is found in the faust.py file.

Connects via SSH to the router (multiple routers are not yet supported), IP and access codes are found in the routers configuration file and transfers all necessary commands to the router.

First it checks wether an acl was already bound, if so: read old acl, save to temporary acl on router and bind temporary acl to interface.
Than copy new acl onto router and bind new acl to interface. Delete temporary acl, if it exists.

If any command triggered an error (any response by router containing '% ' at beginning of line is considered as error), execution is aborted and the bogus command is reported to user. Rollback has to be done manually! All responses from router have to end with a '#', signaling FauST2 that the command executed successfully. Timeout is set to 60 seconds.

Errors checking can be suppressed, this is done for 'no ipv6 access-list ...' commands, as it reports an error if acl was not present. This is also done for transfer of the new acls.
