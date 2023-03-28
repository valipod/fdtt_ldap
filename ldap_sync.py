#!/usr/bin/python3
# -*- coding: utf-8 -*-

from configparser import ConfigParser
from logging.handlers import SysLogHandler
from functools import wraps
from string import ascii_letters, digits
import collections
import getopt
import ldap
import ldap.filter
import logging
import sys
import os
import time
import six

__version__ = """$Id: ldap_sync.py 2020-09-09 18:00:00Z dumitval $"""


RETURN_CODES = {
    'EX_OK':           0,   # successful termination
    'EX_CONFIG':       2,   # missing or incorrect config file
    'EX_LOCKFILE':     4,   # lockfile present
    'EX_DISKERROR':    8,   # disk operation error
    'EX_NETWORK':      16,  # network error
    'EX_SSL':          32,  # SSL error
    'EX_TARGET_NEWER': 64,  # target group has newer timestamp
    'EX_CREDENTIALS':  67,  # invalid LDAP credentials
    'EX_STRUCTURE':    68,  # invalid/unexpected LDAP structure
    'EX_RESPONSE':     69,  # unexpected LDAP response
    'EX_UNIDENTIFIED': 97,  # other error

    'EX_UNAVAILABLE':  69,  # service unavailable
    'EX_SOFTWARE':     70,  # internal software error
    'EX_OSERR':        71,  # system error (e.g., can't fork)
    'EX_OSFILE':       72,  # critical OS file missing
    'EX_CANTCREAT':    73,  # can't create (user) output file
    'EX_IOERR':        74,  # input/output error
    'EX_TEMPFAIL':     75,  # temp failure; user is invited to retry
    'EX_PROTOCOL':     76,  # remote error in protocol
    'EX_NOPERM':       77,  # permission denied
}


sys.tracebacklimit = 0


GROUP_SCHEMA = {
    'description': 'description',
    "memberUid": "member"
}


def usage():
    print("Incorrect arguments. Usage:\n")
    print(
        "%s [-c config-file] [-o logfile] [--debug] [-s/--silent] [-f/--force]"
        % sys.argv[0]
    )
    sys.exit(RETURN_CODES['EX_USAGE'])


def close():
    os.remove('ldap_sync.lock')


try:  # Handle cmd arguments
    opts, args = getopt.getopt(
        sys.argv[1:], "c:o:fs", ['debug', 'force', 'silent']
    )
except getopt.GetoptError:
    usage()

ldap_config = {}
config_file = 'ldap_sync.ini'
logfile = None
force_sync = False
silent = False
expander_config = {}
try:
    for flag, value in opts:
        if flag == '-c':
            config_file = value
        elif flag == '-o':
            logfile = value
        elif flag in ('-f, force'):
            force_sync = True
        elif flag in ('-s', 'silent'):
            silent = True
    config = ConfigParser()
    config.read([config_file])
    sync_config = dict(config.items('sync_config'))
    ldap_config = dict(config.items('ldap_config'))
    if not logfile:
        logfile = config.get('sync_config', 'log')

except KeyError:
    usage()

log = logging.getLogger('ldap_sync')
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

if logfile is not None and logfile != 'syslog':
    log_handler = logging.FileHandler(logfile, 'a')
else:
    log_handler = SysLogHandler('/dev/log',
                                facility=SysLogHandler.LOG_LOCAL6)
    formatter = logging.Formatter(
        "%(name)s: %(levelname)s - %(message)s")
log_handler.setFormatter(formatter)
log.setLevel(logging.INFO)
log.addHandler(log_handler)


def log_message(message):
    if logfile or silent:
        log.info(message)
    else:
        print(message, file=sys.stdout)


def log_error(message):
    if logfile or silent:
        log.exception(message)
    else:
        print(message, file=sys.stderr)


def log_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ''' wrapper '''
        try:
            return func(*args, **kwargs)
        except ldap.LDAPError as e:
            log_error(e)
        except UnexpectedLDAPResponse as e:
            log_error(e)
            return RETURN_CODES['EX_RESPONSE']
        except InvalidLDAPStructure as e:
            log_error(e)
            return RETURN_CODES['EX_STRUCTURE']
        except Exception as e:
            log_error("Uncaught exception from %r, %s" % (func, e))
            return RETURN_CODES['EX_SOFTWARE']

    return wrapper


class InvalidLDAPStructure(Exception):
    ...
    pass


class UnexpectedLDAPResponse(Exception):
    ...
    pass


class LdapAgent(object):

    group_schema = GROUP_SCHEMA

    def __init__(self, **config):
        self.ldap_server = config['ldap_server']
        if not (self.ldap_server.startswith('ldap://') or
                self.ldap_server.startswith('ldaps://')):
            self.ldap_server = 'ldaps://' + self.ldap_server
        self.conn = self.connect()
        self.conn.protocol_version = ldap.VERSION3
        self.conn.simple_bind_s(config['user_dn'].strip(),
                                config['user_pw'].strip())
        self._encoding = config.get('encoding', 'utf-8')
        self._user_dn_suffix = config.get(
            'users_dn',
            "ou=fdt_users,dc=everything,dc=fastdigitech,dc=ro"
        )

    def connect(self):
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        conn = ldap.initialize(self.ldap_server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _ou_dn(self, ou_id, ou_dn_suffix):
        return 'ou=%s,%s' % (ou_id, ou_dn_suffix)

    def _group_id(self, group_dn):
        ''' get group id from group dn '''
        dn_bits = group_dn.split(',')
        if not dn_bits[0].startswith('cn='):
            raise InvalidLDAPStructure(
                "groupOfNames %s does not start with 'cn='" % group_dn
            )

        return dn_bits[0][len('cn='):]

    def _ou_id(self, ou_dn):
        ''' get ou id from ou dn '''
        dn_bits = ou_dn.split(',')
        if not dn_bits[0].startswith('ou='):
            raise InvalidLDAPStructure(
                "organizationalUnit dn %s does not start with 'ou='" % ou_dn
            )

        return dn_bits[0][len('ou='):]

    def _user_id(self, user_dn):
        if not user_dn.endswith(',' + self._user_dn_suffix):
            raise InvalidLDAPStructure(
                "user dn %s doesn't end with ,%s" %
                (user_dn, self._user_dn_suffix)
            )
        if not user_dn.startswith('uid='):
            raise InvalidLDAPStructure(
                "user dn %s doesn't start with 'uid='" % user_dn
            )
        user_id = user_dn[len('uid='): - (len(self._user_dn_suffix) + 1)]
        if ',' in user_id:
            raise InvalidLDAPStructure(
                "',' shouldn't exist in user_id %s" % user_id)
        return user_id

    def _user_dn(self, user_id):
        try:
            user_id = user_id.decode(self._encoding)
        except AttributeError:
            # already str
            pass
        if ',' in user_id:
            raise InvalidLDAPStructure(
                "',' shouldn't exist in user_id %s" % user_id)
        user_dn = 'uid=%s,%s' % (user_id, self._user_dn_suffix)
        return user_dn.encode(self._encoding)

    @log_exceptions
    def delete_dn(self, dn):
        ''' delete LDAP object by dn '''

        result = self.conn.delete_s(dn)
        if result[:2] != (ldap.RES_DELETE, []):
            raise UnexpectedLDAPResponse(
                "result %s is not the expected %s" %
                (result[:2], (ldap.RES_DELETE, []))
            )

    @log_exceptions
    def create_group(self, group_dn, group_info):
        """ Create a new group with attributes from `group_info` """
        log_message("Creating group %r" % group_dn)
        if not isinstance(group_dn, str):
            raise InvalidLDAPStructure(
                "group dn %s is not a plain string" % group_dn
            )

        for ch in group_dn:
            if ch not in ascii_letters + digits + '=_-,':
                raise InvalidLDAPStructure(
                    "char %s is not in ascii + digits + '=_-,'" % ch
                )

        group_id = self._group_id(group_dn)
        attrs = [
            ('cn', [group_id.encode()]),
            ('objectClass', [
                b'top', b'groupOfNames'
            ]
            ),
        ]

        for name, value in sorted(six.iteritems(group_info)):
            if not value:
                continue
            if name in self.group_schema:
                if name == 'memberUid':
                    member_dns = [
                        self._user_dn(uid) for uid in value if uid
                    ]
                    value = member_dns
                attrs.append(
                    (self.group_schema[name], value))
        if not group_info.get("memberUid"):
            attrs.append(('member', [b'']))

        result = self.conn.add_s(group_dn, attrs)

        if result[:2] != (ldap.RES_ADD, []):
            raise UnexpectedLDAPResponse(
                "result %s is not the expected %s" %
                (result[:2], (ldap.RES_ADD, []))
            )

    @log_exceptions
    def create_ou(self, ou_dn):
        """ Create a new organizationalUnit """
        log_message("Creating organizationalUnit %r" % ou_dn)
        if not isinstance(ou_dn, str):
            raise InvalidLDAPStructure(
                "organizationalUnit dn %s is not a plain string" % ou_dn
            )

        for ch in ou_dn:
            if ch not in ascii_letters + digits + '=_-,':
                raise InvalidLDAPStructure(
                    "char %s is not in ascii + digits + '=_-,'" % ch
                )

        attrs = [('objectClass', [b'top', b'organizationalUnit']), ]

        result = self.conn.add_s(ou_dn, attrs)

        if result[:2] != (ldap.RES_ADD, []):
            raise UnexpectedLDAPResponse(
                "result %s is not the expected %s" %
                (result[:2], (ldap.RES_ADD, []))
            )

    @log_exceptions
    def add_member_to_group(self, group_dn, member_dn):
        ''' add member dn to group dn '''
        log_message("Adding member %r to %r" % (member_dn, group_dn))
        result = self.conn.modify_s(group_dn, (
            (ldap.MOD_ADD, 'member', [member_dn]),
        ))

        # If the group didn't have any members, a placeholder b'' was present
        # and now needs to be removed
        try:
            result = self.conn.modify_s(group_dn, (
                (ldap.MOD_DELETE, 'member', [b'']),
            ))
        except ldap.NO_SUCH_ATTRIBUTE:
            pass  # so the group was not empty. that's fine.
        else:
            if result[:2] != (ldap.RES_MODIFY, []):
                raise UnexpectedLDAPResponse(
                    "result %s is not the expected %s" %
                    (result[:2], (ldap.RES_MODIFY, []))
                )
            log_message("Removed placeholder member from %r" % group_dn)

    @log_exceptions
    def remove_member_from_group(self, group_dn, member_dn):
        """ remove a member from a group """
        log_message("Removing member %r from %r" % (member_dn, group_dn))

        def _remove():
            ''' remove '''
            self.conn.modify_s(group_dn, (
                (ldap.MOD_DELETE, 'member', [member_dn]),
            ))

        def _add_placeholder():
            ''' add placeholder '''
            self.conn.modify_s(group_dn, (
                (ldap.MOD_ADD, 'member', [b'']),
            ))

        try:
            _remove()
        except ldap.OBJECT_CLASS_VIOLATION:
            log_message("Adding placeholder uniqueMember for %r" & group_dn)
            _add_placeholder()
            _remove()
        log_message(
            "Removed %s from %s" % (member_dn, group_dn)
        )


class LDAPSync():
    def __init__(self, ldap_agent, **config):
        try:
            self.source_dn = config['source_dn']
            self.target_dn = config['target_dn']
        except KeyError:
            log_error("Invalid ini file")
            close()
            return RETURN_CODES["EX_CONFIG"]
        self.agent = ldap_agent
        self.agent.source_dn = self.source_dn
        self.agent.target_dn = self.target_dn

    @log_exceptions
    def sync(self):
        source_ous = dict(self.agent.conn.search_s(
            self.source_dn,
            ldap.SCOPE_SUBTREE,
            "(&(objectClass=organizationalUnit))",
            attrlist=(["description"])
        ))

        source_groups = dict(self.agent.conn.search_s(
            self.source_dn,
            ldap.SCOPE_SUBTREE,
            "(&(objectClass=posixGroup))",
            attrlist=(["description", "memberUid", "modifyTimestamp"])
        ))

        try:
            destination_groups = dict(self.agent.conn.search_s(
                self.target_dn,
                ldap.SCOPE_SUBTREE,
                "(&(objectClass=groupOfNames))",
                attrlist=(["description", "member", "modifyTimestamp"])
            ))
        except ldap.NO_SUCH_OBJECT:
            self.agent.create_ou(self.target_dn)
            destination_groups = {}

        destination_ous = dict(self.agent.conn.search_s(
            self.target_dn,
            ldap.SCOPE_SUBTREE,
            "(&(objectClass=organizationalUnit))",
            attrlist=(["description"])
        ))
        # First check if there is any ou in destination that was deleted
        # from source
        for dest_dn in destination_ous:
            if dest_dn == self.target_dn:
                continue
            ou_id = self.agent._ou_id(dest_dn)
            source_dn = self.agent._ou_dn(ou_id, self.source_dn)
            if source_dn not in source_ous:
                # Delete the organizationalUnit from destination
                self.agent.delete_dn(dest_dn)
                log_message("Deleted organizationalUnit %s" % dest_dn)
        # Create all source organizationalUnits in destination
        for source_dn in source_ous:
            if source_dn == self.source_dn:
                continue
            ou_id = self.agent._ou_id(source_dn)
            dest_dn = self.agent._ou_dn(ou_id, self.target_dn)
            if dest_dn not in destination_ous:
                self.agent.create_ou(dest_dn)
                log_message("Created organizationalUnit %s" % dest_dn)

        # Check if there is any group in destination that was deleted
        # from source
        for dest_dn in destination_groups:
            source_dn = dest_dn.replace(self.target_dn, self.source_dn)
            if source_dn not in source_groups:
                # Delete the group from destination_groups
                self.agent.delete_dn(dest_dn)
                log_message("Deleted group %s" % dest_dn)
        # Create all source groups in destination_groups
        for source_dn in source_groups:
            dest_dn = source_dn.replace(self.source_dn, self.target_dn)
            if dest_dn in destination_groups:
                # ToDo make the date check and the rest
                source_date = source_groups[source_dn]['modifyTimestamp']
                target_date = destination_groups[dest_dn]['modifyTimestamp']
                if source_date > target_date:
                    source_info = source_groups[source_dn]
                    dest_info = destination_groups[dest_dn]
                    source_members = [
                        self.agent._user_dn(uid) for
                        uid in source_info.get('memberUid', [])
                    ]
                    target_members = dest_info['member']
                    if source_members != target_members:
                        for member in target_members:
                            if member not in source_members:
                                self.agent.remove_member_from_group(
                                    dest_dn, member
                                )
                        for member in source_members:
                            if member not in target_members:
                                self.agent.add_member_to_group(
                                    dest_dn, member
                                )
                                log_message(
                                    "Added %s to %s" % (member, dest_dn)
                                )
            else:
                source_members = source_groups[source_dn].get('memberUid', [])
                if b'' in source_members:
                    log_error("Empty memberUid in %s" % source_dn)
                dupe_source_members = [
                    item for item, count in
                    collections.Counter(source_members).items() if count > 1]
                if dupe_source_members:
                    log_error("Duplicate memberUid entries in %s: %s" %
                              (source_dn, dupe_source_members))
                    source_groups[source_dn]['memberUid'] = set(source_members)
                self.agent.create_group(dest_dn, source_groups[source_dn])
                log_message("Created group %s" % dest_dn)


def main():
    start_time = time.time()
    if os.path.isfile('ldap_sync.lock'):
        log_error("Lockfile present")
        return RETURN_CODES['EX_LOCKFILE']
        sys.exit()
    else:
        open("ldap_sync.lock", "wb")
    try:
        # Open connection with the ldap
        try:
            agent = LdapAgent(**ldap_config)
        except ldap.SERVER_DOWN as e:
            log_error("Cannot connect to LDAP %s; %s" % (
                ldap_config['ldap_server'], e))
            close()
            return RETURN_CODES['EX_NETWORK']
        except ldap.INVALID_CREDENTIALS as e:
            log_error("Cannot connect to LDAP %s; %s" % (
                ldap_config['ldap_server'], e))
            close()
            return RETURN_CODES['EX_CREDENTIALS']
        except Exception as e:
            log_error("Cannot connect to LDAP %s; %s" % (
                ldap_config['ldap_server'], e))
            close()
            return RETURN_CODES['EX_UNIDENTIFIED']

        ldap_sync = LDAPSync(agent, **sync_config)
        ldap_sync.sync()
        os.remove('ldap_sync.lock')
        log_message(
            "The sync was done in %s seconds" % (time.time() - start_time)
        )
    except Exception as e:
        log_error(e)
        close()
        return RETURN_CODES['EX_UNIDENTIFIED']


if __name__ == '__main__':
    sys.exit(main())
