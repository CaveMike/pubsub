#!/usr/bin/env python3
import logging
import unittest

from perm import Perm

class Endpoint(object):
    def __init__(self, perm=None, perms=None):
        if perms is not None:
            self.perms = perms
        elif perm is not None:
            self.perms = perm.to_perms()
        else:
            raise TypeError('specify either perm or perms')

        self.logger = logging.getLogger('Endpoint')

    def __call__(self, publication):
        self.logger.info('notified ' + str(self.perms['r']) + ' of content ' + str(publication))

    def __str__(self):
        return str(self.perms['r'])

    def __repr__(self):
        return 'perm=' + repr(self.perms['r'])

class TestEndpoint(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, Endpoint)

    def test_call(self):
        e = Endpoint(Perm())
        e('content')

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
