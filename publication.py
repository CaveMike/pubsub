#!/usr/bin/env python3
import logging
import unittest

class Publication(object):
    def __init__(self, content, ttl=None):
        self.content = content
        self.ttl = ttl

    def __str__(self):
        return str(self.content)

    def __repr__(self):
        return 'content=' + str(self.content) + ', ttl=' + str(self.ttl)

class TestPublishment(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, Publication)

    def test_init_content(self):
        p = Publication(content='content')
        self.assertIsNotNone(p.content)

    def test_init_both(self):
        p = Publication(content='content', ttl=12)
        self.assertIsNotNone(p.content)
        self.assertEqual(12, p.ttl)

    def test_str(self):
        p = Publication(content='content', ttl=12)
        self.assertIsNotNone(str(p))

    def test_repr(self):
        p = Publication(content='content', ttl=12)
        self.assertIsNotNone(repr(p))

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
