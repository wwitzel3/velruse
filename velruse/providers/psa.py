"""Python Social Auth provider
This wraps the Python Social Auth library and makes the backends
do_auth and do_complete methods available to velruse"""
from collections import defaultdict
from pyramid.security import NO_PERMISSION_REQUIRED

from velruse.api import (
    AuthenticationComplete,
    AuthenticationDenied,
    register_provider,
)

from social.strategy import BaseStrategy

PSA_LOGIN_PROVIDERS_KEY = 'psa_login_providers'


class PSAAuthenticationComplete(AuthenticationComplete):
    """PSA auth complete, this can be from many different providers"""


class PSAAuthenticationDenied(AuthenticationDenied):
    """PSA auth denied, this can be from many different providers"""


class PSAStrategy(BaseStrategy):
    @staticmethod
    def settings(request, name):
        pass


class PSASettings(object):
    def __init__(self, settings, key):
        self.settings = settings
        self.key = key
        self.kwargs = {}

    def update_providers(self):
        """Build a list of dictionaries of PSA providers"""
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
        self.settings = PSAStrategy.settings(request, name)
        self.strategy = PSAStrategy(backend=provider, request=request, storage=None,
                               redirect_uri=self.settings.get('REDIRECT_URI'))
        self.strategy.settings = self.settings
        do_auth(self.strategy)

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
    providers[provider.name] = providers
    settings[PSA_LOGIN_PROVIDERS_KEY] = providers

def add_psa_config_from_settings(config, key='velruse.psa'):
    settings = config.registry.settings
    p = PSASettings(settings, key)
    config.add_psa_config(**p.kwargs)

def add_psa_config(config,
                     providers,
                     login_path='/login/psa.{backend}',
                     callback_path='/login/psa.{backend}/callback'):
    """
    Add routes for PSA backends to the application
    """
    config.add_route('velruse.psa.login', login_path)
    config.add_route('velruse.psa.callback', callback_path)

    provider = PSAProvider(providers)

    config.add_view(view=provider.login, route_name='velruse.psa.login',
                    permission=NO_PERMISSION_REQUIRED, use_global_views=True)
    config.add_view(view=provider.callback, route_name='velruse.psa.callback',
                    use_global_views=True, factory=provider.callback)
