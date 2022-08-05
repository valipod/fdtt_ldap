#!./python3
# -*- coding: utf-8 -*-

from configparser import ConfigParser
from ldap_agent import LdapAgent
from logging.handlers import SysLogHandler
from functools import wraps
import getopt
import ldap
import logging
import sys
import os
import time

__version__ = """$Id: expander.py 40888 2017-04-05 09:47:09Z tiberich $"""


RETURN_CODES = {
    'EX_OK':           0,   # successful termination
    'EX_CONFIG':       2,   # missing or incorrect config file
    'EX_LOCKFILE':     4,   # lockfile present
    'EX_DISKERROR':    8,   # disk operation error
    'EX_NETWORK':      16,  # network error
    'EX_SSL':          32,  # SSL error
    'EX_TARGET_NEWER': 64,  # target group has newer timestamp
    'EX_CREDENTIALS':  67,  # invalid LDAP credentials
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
log = logging.getLogger('ldap_sync')
log.setLevel(logging.DEBUG)
stream_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)


def usage():
    print("Incorrect arguments. Usage:\n")
    print("%s [-c config-file] [-o logfile] [--debug] [-s/--silent] [-f/--force]"
          % sys.argv[0])
    sys.exit(RETURN_CODES['EX_USAGE'])


def close():
    os.remove('ldap_sync.lock')


try:  # Handle cmd arguments
    opts, args = getopt.getopt(
        sys.argv[1:], "c:o:fs", ['debug', 'force', 'silent']
    )
except getopt.GetoptError:
    usage()

logfile = None
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

if logfile is not None:
    log_handler = logging.FileHandler(logfile, 'a')
    log_handler.setFormatter(formatter)
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
        try:
            return func(*args, **kwargs)
        except Exception:
            log.exception("Uncaught exception from %r", func)
            return RETURN_CODES['EX_SOFTWARE']

    return wrapper


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
        sources = dict(self.agent.conn.search_s(
            self.source_dn,
            ldap.SCOPE_SUBTREE,
            "(&(objectClass=posixGroup))",
            attrlist=(["description", "memberUid", "modifyTimestamp"])
        ))
        destination = dict(self.agent.conn.search_s(
            self.target_dn,
            ldap.SCOPE_SUBTREE,
            "(&(objectClass=groupOfNames))",
            attrlist=(["description", "member", "modifyTimestamp"])
        ))
        # First check if there is any group in destination ou that was deleted
        # from source
        for dest_dn in destination:
            group_id = self.agent._target_id(dest_dn)
            source_dn = self.agent._source_dn(group_id)
            if source_dn in sources:
                pass
            else:
                # Delete the group from destination
                self.agent.delete_group(dest_dn)
                log_message("Deleted group %s" % dest_dn)
        # Create all source groups in destination
        for source_dn in sources:
            group_id = self.agent._source_id(source_dn)
            dest_dn = self.agent._target_dn(group_id)
            if dest_dn in destination:
                # ToDo make the date check and the rest
                source_date = sources[source_dn]['modifyTimestamp']
                target_date = destination[dest_dn]['modifyTimestamp']
                if source_date > target_date:
                    source_info = sources[source_dn]
                    dest_info = destination[dest_dn]
                    source_members = [
                        self.agent._user_dn(uid) for
                        uid in source_info['memberUid']
                    ]
                    target_members = dest_info['member']
                    if source_members != target_members:
                        for member in target_members:
                            if member not in source_members:
                                self.agent.remove_member_from_group(
                                    dest_dn, member
                                )
                                log_message(
                                    "Removed %s from %s" %(member, dest_dn)
                                )
                        for member in source_members:
                            if member not in target_members:
                                self.agent.add_member_to_group(
                                    dest_dn, member
                                )
                                log_message(
                                    "Added %s to %s" %(member, dest_dn)
                                )
            else:
                self.agent.create_group(group_id, sources[source_dn])
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
        log_message("The sync was done in %s seconds" % (time.time() - start_time))
    except Exception as e:
        log_error(e)
        close()
        return RETURN_CODES['EX_UNIDENTIFIED']


if __name__ == '__main__':
    sys.exit(main())
