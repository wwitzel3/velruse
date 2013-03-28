import unittest2 as unittest
from pyramid import testing

from velruse.providers.psa import PSASettings

settings = {
    'login_providers': '\npsa',
    'velruse.psa': '\nfacebook.consumer_key = XXX\nfacebook.consumer_secret = XXX\ntwitter.consumer_key = YYY\ntwitter.consumer_secret = YYY',
}

class TestPSASettings(unittest.TestCase):
    def setUp(self):
        self.config = testing.setUp(settings=settings)

    def test_provider_parsing(self):
        settings = self.config.registry.settings
        p = PSASettings(settings, 'velruse.psa')
        p.update_providers()

        providers = p.kwargs['providers']

        self.assertIn('facebook', providers)
        self.assertIn('twitter', providers)

        self.assertIn('consumer_key', providers['facebook'])
        self.assertIn('consumer_secret', providers['twitter'])

        self.assertEquals(providers['facebook']['consumer_secret'], 'XXX')
        self.assertEquals(providers['twitter']['consumer_key'], 'YYY')
