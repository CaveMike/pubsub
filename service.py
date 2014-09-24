#!/usr/bin/env python3
import logging
import unittest
import itertools

from endpoint import Endpoint
from perm import Perm
from provider import Provider
from publication import Publication

class Service(object):
    def __init__(self, perms):
        self.provider = Provider(perms=perms)

    def register(self, endpoint):
        self.provider.create_endpoint(endpoint)

    def unregister(self, endpoint):
        self.provider.delete_endpoint(endpoint)
        # TODO: Remove subscriptions

    def publish(self, topic, publication, endpoint, perms=None):
        n = self.provider.get_node(topic, perms=endpoint.perms)
        if not n:
            if not perms:
                perms = endpoint.perms
            n = self.provider.create_node(topic, perms=perms)

        return n.publish(publication=publication, perms=endpoint.perms)

    def subscribe(self, topic, endpoint):
        n = self.provider.get_node(topic, perms=endpoint.perms)
        if not n:
            # FIXME: raise an error?  should we be allowed to subscribe before a node is published to?
            return

        return n.subscribe(endpoint=endpoint, perms=endpoint.perms)

    def read(self, topic, endpoint):
        n = self.provider.get_node(topic, perms=endpoint.perms)
        if not n:
            return None

        # TODO: Is this supposed to notify the endpoint?
        return n.read(perms=endpoint.perms)

class TestService(unittest.TestCase):
    def setUp(self):
        p = Perm(gid=('admin', 'user'))
        perms = p.to_perms()
        self.s = Service(perms)

        self.mike = Endpoint(Perm(gid='user', uid='mike'))
        self.s.register(self.mike)

        self.chloe = Endpoint(Perm(gid=('admin', 'user'), uid='chloe'))
        self.s.register(self.chloe)

        self.ta = 'status'
        self.blog = 'blog'

    def test_prepublish(self):
        self.s.publish(topic=self.blog, publication=Publication('version0'), endpoint=self.mike)

    def test_subscribe(self):
        self.assertRaises(PermissionError, subscription=self.s.subscribe, topic=self.ta, endpoint=self.mike)
        self.s.subscribe(topic=self.ta, endpoint=self.chloe)
        self.s.subscribe(topic=self.blog, endpoint=self.mike)
        self.s.subscribe(topic=self.blog, endpoint=self.chloe)

    def test_publish0(self):
        p = Perm(gid=('admin', ))
        perms = p.to_perms()
        self.s.publish(topic=self.ta, publication=Publication('admin version1'), endpoint=self.chloe, perms=perms)
        self.assertRaises(PermissionError, self.s.publish, topic=self.ta, publication=Publication('fails'), endpoint=self.mike)

    def test_publish1(self):
        self.s.publish(topic=self.ta, publication=Publication('admin version1'), endpoint=self.chloe)

    def test_publish2(self):
        self.s.publish(topic=self.blog, publication=Publication('version1'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publication=Publication('version2'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publication=Publication('version3'), endpoint=self.mike)

    def test_publish3(self):
        self.s.publish(topic=self.blog, publication=Publication('fails'), endpoint=self.chloe)

    def test_read0(self):
        self.s.publish(topic=self.ta, publication=Publication('admin version1'), endpoint=self.chloe)

    def test_read1(self):
        self.s.publish(topic=self.ta, publication=Publication('admin version1'), endpoint=self.chloe)
        self.assertEqual('admin version1', self.s.read(topic=self.ta, endpoint=self.chloe).content)

    def test_read2(self):
        self.s.publish(topic=self.blog, publication=Publication('version1'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publication=Publication('version2'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publication=Publication('version3'), endpoint=self.mike)
        self.assertEqual('version3', self.s.read(topic=self.blog, endpoint=self.mike).content)
        self.assertEqual('version3', self.s.read(topic=self.blog, endpoint=self.chloe).content)

    def test_read3(self):
        self.s.publish(topic=self.blog, publication=Publication('version1'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publication=Publication('version2'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publication=Publication('version3'), endpoint=self.mike)
        self.assertEqual('version3', self.s.read(topic=self.blog, endpoint=self.chloe).content)

    def test_read(self):
        p = Perm(gid=('admin', ))
        perms = p.to_perms()
        self.s.publish(topic=self.ta, publication=Publication('admin version1'), endpoint=self.chloe, perms=perms)
        self.assertRaises(PermissionError, self.s.read, topic=self.ta, endpoint=self.mike)

    def test_delete_endpoint(self):
        self.s.unregister(self.mike)
        self.s.unregister(self.chloe)

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
