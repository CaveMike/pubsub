#!/usr/bin/env python3
import logging
import unittest

from endpoint import Endpoint
from key import Key
from tnode import TopicNode
from perm import Perm

class Provider(object):
    def __init__(self, perms=None):
        self.endpoints = set()
        self.root = TopicNode('<root>', perms=perms)

    def create_endpoint(self, endpoint):
        self.endpoints.add(endpoint)

    def delete_endpoint(self, endpoint):
        self.endpoints.remove(endpoint)

    def get_node(self, topic, perms=None):
        return self.root.get_node(topic, perms=perms)

    def create_node(self, topic, perms=None):
        return self.root.create_child(topic, perms=perms)

    def delete_node(self, topic, perms=None):
        return self.root.delete_child(topic, perms=perms)

class TestProvider(unittest.TestCase):
    def setUp(self):
        self.s = Provider()

        self.mike = Endpoint(Perm(gid='user', uid='mike'))
        self.s.create_endpoint(self.mike)

        self.chloe = Endpoint(Perm(gid='admin', uid='chloe'))
        self.s.create_endpoint(self.chloe)

        self.ta = 'status'
        self.blog = 'blog'

    def test_create_node(self):
        s = Provider()
        s.create_node(Key('a.aa.aaa'))
        s.create_node(Key('b.ba.baa.baaa'))
        s.create_node(Key('b.ba.bab.baba'))
        l = [n for n in s.root.prefix()]
        self.assertEqual(10, len(l))

    def test_delete_endpoint(self):
        self.s.delete_endpoint(self.mike)
        self.s.delete_endpoint(self.chloe)

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
