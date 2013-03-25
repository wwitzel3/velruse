"""Python Social Auth provider
This wraps the Python Social Auth library and makes the backends
do_auth and do_complete methods available to velruse"""

from pyramid.security import NO_PERMISSION_REQUIRED

from velruse.api import (
    AuthenticationComplete,
    AuthenticationDenied,
    register_provider,
)

class PSAAuthenticationComplete(AuthenticationComplete):
    """PSA auth complete, this can be from many different providers"""


class PSASettings(object):
    pass


class PSAProvider(object):
    def __init__(self, name):
        pass

    def login(self, request):
        pass

    def callback(self, request):
        pass

def includeme(config):
    config.add_directive('add_psa_provider', add_psa_providers)
    config.add_directive('add_psa_provider_from_settings',
                         add_psa_provider_from_settings)

def add_psa_provider_from_settings(config, prefix='velruse.psa.'):
    settings = config.registry.settings
    p = PSASettings(settings, prefix)
    config.add_psa_providers(**p.kwargs)

def add_psa_providers(config,
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
