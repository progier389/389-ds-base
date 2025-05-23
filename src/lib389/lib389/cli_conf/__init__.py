# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2019 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
import ldap
from lib389 import ensure_list_str
from lib389.cli_base import CustomHelpFormatter


def _args_to_attrs(args, arg_to_attr):
    attrs = {}
    for arg in vars(args):
        val = getattr(args, arg)
        if arg in arg_to_attr and val is not None:
            attrs[arg_to_attr[arg]] = val
        elif arg == 'DN':
            # Extract RDN from the DN
            attribute = ldap.dn.str2dn(val)[0][0][0]
            value = ldap.dn.str2dn(val)[0][0][1]
            attrs[attribute] = value
    return attrs


def generic_object_add(dsldap_objects_class, inst, log, args, arg_to_attr, dn=None, basedn=None, props={}):
    """Create an entry using DSLdapObjects interface

    dsldap_objects should be a class inherited from the DSLdapObjects class
    """

    log = log.getChild('generic_object_add')
    # If Base DN was initially provided then 'props' should contain the RDN
    # if 'props' doesn't have the RDN - it will fail with the right error during the validation in the 'create'
    rdn = None
    # Gather the attributes
    attrs = _args_to_attrs(args, arg_to_attr)
    props.update({attr: value for (attr, value) in attrs.items() if value != "" and value != [""]})

    # Get RDN attribute and Base DN from the DN if Base DN is not specified
    if basedn is None:
        if dn is not None:
            dn_parts = ldap.dn.explode_dn(dn)
            rdn = dn_parts[0]
            basedn = ",".join(dn_parts[1:])
        else:
            raise ValueError('If Base DN is not specified - DN parameter should be specified instead')

    new_object = dsldap_objects_class(inst, dn=dn)
    new_object.create(rdn=rdn, basedn=basedn, properties=props)
    log.info("Successfully created the %s", new_object.dn)
    return new_object


def generic_object_add_attr(dsldap_object, log, args, arg_to_attr):
    """Add an attribute to the entry. This differs to 'edit' as edit uses replace,
    and this allows multivalues to be added.

    dsldap_object should be a single instance of DSLdapObject with a set dn
    """
    log = log.getChild('generic_object_add_attr')
    # Gather the attributes
    attrs = _args_to_attrs(args, arg_to_attr)

    modlist = []
    for attr, value in attrs.items():
        if not isinstance(value, list):
            value = [value]
        modlist.append((ldap.MOD_ADD, attr, value))
    if len(modlist) > 0:
        dsldap_object.apply_mods(modlist)
        log.info("Successfully changed the %s", dsldap_object.dn)
    else:
        raise ValueError("There is nothing to set in the %s plugin entry" % dsldap_object.dn)

def generic_object_del_attr(dsldap_object, log, args, arg_to_attr):
    """Delete an attribute from an entry.

    dsldap_object should be a single instance of DSLdapObject with a set dn
    """
    log = log.getChild('generic_object_del_attr')
    # Gather the attributes
    attrs = _args_to_attrs(args, arg_to_attr)

    modlist = []
    for attr, value in attrs.items():
        if not isinstance(value, list):
            value = [value]
        modlist.append((ldap.MOD_DELETE, attr, value))
    if len(modlist) > 0:
        dsldap_object.apply_mods(modlist)
        log.info("Successfully changed the %s", dsldap_object.dn)
    else:
        raise ValueError("There is nothing to delete in the %s plugin entry" % dsldap_object.dn)

def generic_object_edit(dsldap_object, log, args, arg_to_attr):
    """Replace or delete an attribute on an entry.

    dsldap_object should be a single instance of DSLdapObject with a set dn
    """

    log = log.getChild('generic_object_edit')
    # Gather the attributes
    attrs = _args_to_attrs(args, arg_to_attr)
    existing_attributes = dsldap_object.get_all_attrs()

    modlist = []
    unchanged_attrs = {}

    for attr, value in attrs.items():
        # Delete the attribute only if the user set it to 'delete' value
        if value in ("delete", ["delete"]):
            if attr in existing_attributes:
                modlist.append((ldap.MOD_DELETE, attr))
        else:
            if not isinstance(value, list):
                value = [value]
            if not (attr in existing_attributes and value == ensure_list_str(existing_attributes[attr])):
                modlist.append((ldap.MOD_REPLACE, attr, value))
            else:
                # Track attributes that didn't change for better error messages
                unchanged_attrs[attr] = value

    if len(modlist) > 0:
        dsldap_object.apply_mods(modlist)
        log.info("Successfully changed the %s", dsldap_object.dn)
    else:
        # Check if we're trying to enable/disable a plugin and it's already in that state
        enabled_attr = arg_to_attr.get('enabled', None)
        if enabled_attr in unchanged_attrs:
            # Get the current state for a more informative message
            current_state = ensure_list_str(existing_attributes[enabled_attr])[0]
            if current_state.lower() == 'on':
                log.info("Plugin '%s' is already enabled" % dsldap_object.rdn)
            else:
                log.info("Plugin '%s' is already disabled" % dsldap_object.rdn)
        else:
            raise ValueError("There is nothing to change in the %s entry" % dsldap_object.dn)


def generic_show(inst, basedn, log, args):
    """Display plugin configuration."""
    plugin = args.plugin_cls(inst)
    log.info(plugin.display())


def generic_enable(inst, basedn, log, args):
    plugin = args.plugin_cls(inst)
    if plugin.status():
        log.info("Plugin '%s' already enabled" % plugin.rdn)
    else:
        plugin.enable()
        log.info("Enabled plugin '%s'" % plugin.rdn)


def generic_disable(inst, basedn, log, args):
    plugin = args.plugin_cls(inst)
    if not plugin.status():
        log.info("Plugin '%s' already disabled" % plugin.rdn)
    else:
        plugin.disable()
        log.info("Disabled plugin '%s'" % plugin.rdn)


def generic_status(inst, basedn, log, args):
    plugin = args.plugin_cls(inst)
    if plugin.status() is True:
        log.info("Plugin '%s' is enabled" % plugin.rdn)
    else:
        log.info("Plugin '%s' is disabled" % plugin.rdn)


def add_generic_plugin_parsers(subparser, plugin_cls):
    show_parser = subparser.add_parser('show', help='Displays the plugin configuration', formatter_class=CustomHelpFormatter)
    show_parser.set_defaults(func=generic_show, plugin_cls=plugin_cls)

    enable_parser = subparser.add_parser('enable', help='Enables the plugin', formatter_class=CustomHelpFormatter)
    enable_parser.set_defaults(func=generic_enable, plugin_cls=plugin_cls)

    disable_parser = subparser.add_parser('disable', help='Disables the plugin', formatter_class=CustomHelpFormatter)
    disable_parser.set_defaults(func=generic_disable, plugin_cls=plugin_cls)

    status_parser = subparser.add_parser('status', help='Displays the plugin status', formatter_class=CustomHelpFormatter)
    status_parser.set_defaults(func=generic_status, plugin_cls=plugin_cls)


