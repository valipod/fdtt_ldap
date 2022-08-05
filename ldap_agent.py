# -*- coding: utf-8 -*-
from string import ascii_letters, digits
from functools import wraps
import ldap
import ldap.filter
import six

__version__ = """$Id$"""


def log_ldap_exceptions(func):
    ''' log_ldap_exceptions '''
    @wraps(func)
    def wrapper(*args, **kwargs):
        ''' wrapper '''
        try:
            return func(*args, **kwargs)
        except ldap.LDAPError:
            #log.exception("Uncaught exception from LDAP")
            raise

    return wrapper


GROUP_SCHEMA = {
    'description': 'description',
    "memberUid": "member"
}


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
        conn = ldap.initialize(self.ldap_server)
        conn.protocol_version = ldap.VERSION3
        return conn

    def _source_dn(self, group_id):
        return self._group_dn(group_id, self.source_dn)

    def _target_dn(self, group_id):
        return self._group_dn(group_id, self.target_dn)

    def _group_dn(self, group_id, group_dn_suffix):
        if group_id is None:
            id_bits = []
        else:
            id_bits = group_id.split('-')

        dn_start = ''
        for c in range(len(id_bits), 0, -1):
            dn_start += 'cn=%s,' % '-'.join(id_bits[:c])
        return dn_start + group_dn_suffix

    def _source_id(self, group_dn):
        ''' get source group id from group dn '''
        return self._group_id(group_dn, self.source_dn)

    def _target_id(self, group_dn):
        ''' get source group id from group dn '''
        return self._group_id(group_dn, self.target_dn)

    def _group_id(self, group_dn, group_dn_suffix):
        ''' get group id from group dn '''
        if group_dn == group_dn_suffix:
            return None
        assert group_dn.endswith(',' + group_dn_suffix)
        group_dn_start = group_dn[: - (len(group_dn_suffix) + 1)]
        dn_bits = group_dn_start.split(',')
        dn_bits.reverse()

        current_bit = None

        for bit in dn_bits:
            assert bit.startswith('cn=')
            bit = bit[len('cn='):]

            if current_bit is None:
                assert '-' not in bit
            else:
                assert bit.startswith(current_bit + '-')
                assert '-' not in bit[len(current_bit) + 1:]
            current_bit = bit

        return current_bit

    def _user_id(self, user_dn):
        assert user_dn.endswith(',' + self._user_dn_suffix)
        assert user_dn.startswith('uid=')
        user_id = user_dn[len('uid='): - (len(self._user_dn_suffix) + 1)]
        assert ',' not in user_id
        return user_id

    def _user_dn(self, user_id):
        try:
            user_id = user_id.decode(self._encoding)
        except AttributeError:
            pass
        assert ',' not in user_id
        user_dn = 'uid=' + user_id + ',' + self._user_dn_suffix
        return user_dn.encode(self._encoding)

    @log_ldap_exceptions
    def delete_group(self, group_dn):
        ''' delete group '''

        for dn in self._sub_groups(group_dn):
            result = self.conn.delete_s(dn)
            assert result[:2] == (ldap.RES_DELETE, [])

    @log_ldap_exceptions
    def create_group(self, group_id, group_info):
        """ Create a new group with attributes from `group_info` """
        #log.info("Creating group %r", group_id)
        assert isinstance(group_id, str)

        for ch in group_id:
            assert ch in ascii_letters + digits + '_'

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
                        self._user_dn(member) for member in value
                    ]
                    value = member_dns
                attrs.append(
                    (self.group_schema[name], value))
        if not group_info.get("memberUid"):
            attrs.append(('member', [b'']))

        group_dn = self._target_dn(group_id)
        result = self.conn.add_s(group_dn, attrs)

        assert result[:2] == (ldap.RES_ADD, [])

    @log_ldap_exceptions
    def add_member_to_group(self, group_dn, member_dn):
        ''' add member dn to group dn '''
        #log.info("Adding member %r to %r", member_dn, group_dn)
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
            assert result[:2] == (ldap.RES_MODIFY, [])
            #log.info("Removed placeholder member from %r", group_dn)

    @log_ldap_exceptions
    def remove_member_from_group(self, group_dn, member_dn):
        """ remove a member from a group """
        #log.info("Removing member %r from %r", member_dn, group_dn)

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
            #log.info("Adding placeholder uniqueMember for %r", group_dn)
            _add_placeholder()
            _remove()
