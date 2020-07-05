import logging
import tornado.web
import tornado.ioloop


from tornado.options import options
from webssh import handler
from webssh.handler import IndexHandler, WsockHandler, NotFoundHandler
from webssh.settings import (
    get_app_settings,  get_host_keys_settings, get_policy_setting,
    get_ssl_context, get_server_settings, check_encoding_setting, get_ldap_settings
)

from webssh.auth import LdapAuthMixin, auth_required

class AuthHandler(LdapAuthMixin, IndexHandler):

    def initialize(self, loop, policy, host_keys_settings, ldap_settings):
        super(IndexHandler, self).initialize(loop)
        self.ldap_auth = ldap_settings.get('ldap_auth')
        self.ldap_host = ldap_settings.get('ldap_host')
        self.ldap_port = ldap_settings.get('ldap_port')
        self.ldap_peopledn = ldap_settings.get('ldap_peopledn')
        self.ldap_groupdn = ldap_settings.get('ldap_groupdn')
        self.debug = self.settings.get('debug', False)
        self.font = self.settings.get('font', '')
        self.result = dict(id=None, status=None, encoding=None)
        self.policy = policy
        self.host_keys_settings = host_keys_settings
        self.ssh_client = self.get_ssh_client()

    @auth_required(realm="Protected")
    def get(self):
        return super(AuthHandler, self).get()


def make_handlers(loop, options):
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)
    ldap_settings = get_ldap_settings(options)

    handlers = [
        (r'/', AuthHandler, dict(loop=loop, policy=policy,
                                  host_keys_settings=host_keys_settings,
                                  ldap_settings=ldap_settings)),
        (r'/ws', WsockHandler, dict(loop=loop))
    ]
    return handlers


def make_app(handlers, settings):
    settings.update(default_handler_class=NotFoundHandler)
    return tornado.web.Application(handlers, **settings)


def app_listen(app, port, address, server_settings):
    app.listen(port, address, **server_settings)
    if not server_settings.get('ssl_options'):
        server_type = 'http'
    else:
        server_type = 'https'
        handler.redirecting = True if options.redirect else False
    logging.info(
        'Listening on {}:{} ({})'.format(address, port, server_type)
    )


def main():
    options.parse_command_line()
    check_encoding_setting(options.encoding)
    loop = tornado.ioloop.IOLoop.current()
    app = make_app(make_handlers(loop, options), get_app_settings(options))
    ssl_ctx = get_ssl_context(options)
    server_settings = get_server_settings(options)
    app_listen(app, options.port, options.address, server_settings)
    if ssl_ctx:
        server_settings.update(ssl_options=ssl_ctx)
        app_listen(app, options.sslport, options.ssladdress, server_settings)
    loop.start()


if __name__ == '__main__':
    main()
