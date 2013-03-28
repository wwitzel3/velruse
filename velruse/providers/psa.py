"""Python Social Auth provider
This wraps the Python Social Auth library and makes the backends
do_auth and do_complete methods available to velruse"""
from collections import defaultdict

from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.httpexceptions import HTTPFound

from velruse.api import (
    AuthenticationComplete,
    AuthenticationDenied,
)

from social.strategies.base import BaseStrategy
from social.apps.actions import (
    do_auth,
    do_complete,
)
from social.exceptions import (
    AuthFailed,
    AuthCanceled,
)

PSA_LOGIN_PROVIDERS_KEY = 'psa_login_providers'


class PSAAuthenticationComplete(AuthenticationComplete):
    """PSA auth complete, this can be from many different providers"""


class PSAAuthenticationDenied(AuthenticationDenied):
    """PSA auth denied, this can be from many different providers"""


class PSAStrategy(BaseStrategy):
    def request_data(self, merge=True):
        if self.request.method == 'POST':
            return self.request.POST
        else:
            return self.request.GET

    def get_setting(self, name):
        return self.settings[name]

    def session_set(self, name, value):
        self.request.session[name] = value

    def session_get(self, name, default=None):
        return self.request.session.get(name, default)

    def session_pop(self, name):
        try:
            return self.request.session.pop(name)
        except KeyError:
            return None

    def redirect(self, url):
        raise HTTPFound(location=url)

    def authenticate(self, *args, **kwargs):
        """At this point we have all of the details from the request ..."""
        kwargs['strategy'] = self
        kwargs['storage'] = self.storage
        kwargs['backend'] = self.backend
        return self.backend.authenticate(*args, **kwargs)

    def build_absolute_uri(self, path=None):
        path = path or ''
        if path.startswith('http://') or path.startswith('https://'):
            return path
        if self.request.host_url.endswith('/') and path.startswith('/'):
            path = path[1:]
        return self.request.host_url + (path or '')

    @staticmethod
    def settings(request, providers, name):
        provider = providers[name]
        scope = provider.get('scope',[])
        if scope:
            scope = [s.strip() for s in scope.split(',')]
        return dict(
            KEY=provider['consumer_key'],
            SECRET=provider['consumer_secret'],
            SCOPE=scope,
            REDIRECT_URI=request.route_url('velruse.psa.callback', backend=name),
        )

class PSASettings(object):
    def __init__(self, settings, key):
        self.settings = settings
        self.key = key
        self.kwargs = {}

    def update_providers(self):
        """Build a list of dictionaries of PSA providers"""
        if not self.key in self.settings:
            raise KeyError('missing required setting "%s"' % self.key)

        provider_list = self.settings[self.key]
        provider_list = filter(None, [p.strip()
                                  for line in provider_list.splitlines()
                                  for p in line.split(', ')])
        providers = defaultdict(dict)
        for provider_string in provider_list:
           name, option = provider_string.split('.')
           key, val = [o.strip() for o in option.split('=')]
           providers[name].update({key:val})
        self.kwargs['providers'] = providers


class PSAProvider(object):
    def __init__(self, providers):
        self.providers = providers

    def login(self, request):
        name, provider = self.locate_provider(request)
        settings = PSAStrategy.settings(request, self.providers, name)
        strategy = PSAStrategy(backend=provider, request=request, storage=None,
                               redirect_uri=settings.get('REDIRECT_URI'))
        strategy.settings = settings
        do_auth(strategy)

    def callback(self, request):
        name, provider = self.locate_provider(request)
        try:
            do_complete(strategy, login=request.session.get('user_id'))
        except (AuthFailed, AuthCanceled):
            return PSAAuthenticationDenied(provider_name=name)

    def locate_provider(self, request):
        provider_name = request.matchdict['backend']
        providers = request.registry.settings.get(PSA_LOGIN_PROVIDERS_KEY)
        return (provider_name, providers[provider_name])


def includeme(config):
    config.add_directive('add_psa_config', add_psa_config)
    config.add_directive('add_psa_config_from_settings',
                         add_psa_config_from_settings)
    config.add_directive('register_psa_provider_class', register_psa_provider_class)

def register_psa_provider_class(config, provider):
    settings = config.registry.settings
    providers = settings.get(PSA_LOGIN_PROVIDERS_KEY, dict())
    providers[provider.name] = provider
    settings[PSA_LOGIN_PROVIDERS_KEY] = providers

def add_psa_config_from_settings(config, key='velruse.psa'):
    settings = config.registry.settings
    p = PSASettings(settings, key)
    p.update_providers()
    config.add_psa_config(**p.kwargs)

def add_psa_config(config,
                   providers,
                   login_path='/login/psa.{backend}',
                   callback_path='/login/psa.{backend}/callback'):
    """
    Add routes for PSA backends to the application
    """
    provider = PSAProvider(providers)
    config.add_route('velruse.psa.login', login_path, use_global_views=True)
    config.add_route('velruse.psa.callback', callback_path,
                     factory=provider.callback, use_global_views=True)

    config.add_view(view=provider.login, route_name='velruse.psa.login',
                    permission=NO_PERMISSION_REQUIRED)
    config.add_view(view=provider.callback, route_name='velruse.psa.callback')
