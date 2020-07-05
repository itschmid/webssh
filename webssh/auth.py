import os, re, sys
import time
import binascii
import base64
import hashlib
from ldap3 import *
from ldap3.core.exceptions import *




class LdapAuthMixin(object):

    class SendChallenge(Exception):
        pass

    def ldap_login(self, username, password):

        try:
            userdn = "uid=%s,%s" % (username, self.ldap_peopledn)

            server = Server(self.ldap_host, port=self.ldap_port)
            conn = Connection(server=server,
                              user=userdn,
                              password=password,
                              raise_exceptions=True,
                              auto_bind=True,
                              receive_timeout=60)
            conn.bind()
            conn.search(search_base=self.ldap_groupdn, search_filter="(&(objectClass=groupOfNames)(cn=*))",
                        search_scope=BASE, attributes=['*'])
        except LDAPException as e:
            print(e)
            return False

        entry = conn.entries[0]
        entry_dict = entry.entry_attributes_as_dict

        if not userdn in entry_dict['member']:
            return False
        return True

    def get_authenticated_user(self, realm):
        if self.ldap_auth:
            try:
                return self.authenticate_user(realm)
            except self.SendChallenge:
                self.send_auth_challenge(realm)
        else:
            return True

    def send_auth_challenge(self, realm):
        hdr = 'Basic realm="%s"' % realm.replace('\\', '\\\\').replace('"', '\\"')
        self.set_status(401)
        self.set_header('www-authenticate', hdr)
        self.finish()
        return False

    def authenticate_user(self, realm):
        auth_header = self.request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            raise self.SendChallenge()

        auth_data = auth_header.split(None, 1)[-1]
        auth_data = base64.b64decode(auth_data).decode('ascii')
        username, password = auth_data.split(':', 1)

        if self.ldap_login(username, password):
            self._current_user = username
            return True
        else:
            raise self.SendChallenge()

        return False


def auth_required(realm):
    '''Decorator that protect methods with HTTP authentication.'''
    def auth_decorator(func):
        def inner(self, *args, **kw):
            if self.get_authenticated_user(realm):
                return func(self, *args, **kw)
        return inner
    return auth_decorator