#!/usr/bin/env python3
import logging
import unittest

def is_sequence(arg):
    return not hasattr(arg, 'strip') and hasattr(arg, '__getitem__') and hasattr(arg, '__iter__')

class TestIsSeq(unittest.TestCase):
    def test_string(self):
        self.assertFalse(is_sequence('test'))

    def test_tuple_string(self):
        self.assertTrue(is_sequence(('test', )))

    def test_tuple_strings(self):
        self.assertTrue(is_sequence(('test0', 'test1')))

    def test_list_string(self):
        self.assertTrue(is_sequence(['test', ]))

    def test_list_strings(self):
        self.assertTrue(is_sequence(['test0', 'test1']))

def is_sequence_or_set(arg):
    return isinstance(arg, set) or is_sequence(arg)

class TestIsSeqOrSet(unittest.TestCase):
    def test_set_string(self):
        self.assertTrue(is_sequence_or_set(set('test', )))

    def test_set_strings(self):
        self.assertTrue(is_sequence_or_set(set(('test0', 'test1'))))

class node(object):
    SEPARATOR = '.'

    def check_keys(keys):
        if isinstance(keys, str):
            return keys.split(node.SEPARATOR)
        elif not hasattr(keys, '__iter__'):
            raise TypeError('invalid keys')
        elif not hasattr(keys, 'pop'):
            # If keys is iter-able, but not pop-able, then convert it into a list.
            return list(keys)

        return keys

    def __init__(self, key, parent=None, data=None, owner=None):
        self.key = key

        self.parent = parent
        if self.parent:
            self.parent.children[self.key] = self

        self.children = {}

        self.data = data
        self.owner = owner

    def delete(self):
        if self.parent:
            del self.parent.children[self.key]

    def create_child(self, keys):
        if not keys:
            return self

        # Find the closest existing node.
        n, subkeys = self.find_closest(keys)

        # Create new nodes.
        for subkey in subkeys:
            n = node(subkey, n)

        # Return the new child.
        return n

    def delete_child(self, keys):
        # Find the child.
        n = self.get_node(keys)

        # If the child does not exist, fail.
        if not n:
            return None

        n.delete()

        # Return the deleted child.
        return n

    def find_closest(self, keys):
        if not keys:
            return self, ()

        keys = node.check_keys(keys)

        try:
            s = self
            while len(keys):
                subkey = keys[0]
                s = s.children[subkey]
                keys.pop(0)
        except KeyError:
            pass

        # Return the closest and the remaining keys.
        return s, keys

    def has_node(self, keys):
        parent, subkeys = self.find_closest(keys)
        return not len(subkeys)

    def get_node(self, keys):
        parent, subkeys = self.find_closest(keys)
        if not len(subkeys):
            return parent

        return None

    def ancestors(self):
        if self.parent:
            yield from self.parent.self_and_ancestors()

    def self_and_ancestors(self):
        yield self
        yield from self.ancestors()

    def descendents(self):
        for key, child in self.children.items():
            yield from child.prefix()

    def prefix(self):
        yield self
        yield from self.descendents()

    def postfix(self):
        yield from self.descendents()
        yield self

    def __str__(self):
        return 'key=' + str(self.key)

    def __repr__(self):
        return 'key=' + repr(self.key) + ', parent=' + repr(self.parent) + ', children=' + repr(self.children) + ', data=' + repr(self.data)

class TestNode(unittest.TestCase):
    def setUp(self):
        self.r = node('r')
        self.a = node('a', self.r)
        self.aa = node('aa', self.a)
        self.ab = node('ab', self.a)
        self.aba = node('aba', self.ab)
        self.abaa = node('abaa', self.aba)
        self.ac = node('ac', self.a)
        self.b = node('b', self.r)
        self.c = node('c', self.r)
        self.ca = node('ca', self.c)
        self.cb = node('cb', self.c)

    def test_init_none(self):
        self.assertRaises(TypeError, node)

    def test_init_key(self):
        s = node('key')
        self.assertEqual('key', s.key)
        self.assertIsNone(s.parent)
        self.assertEqual(0, len(s.children))

    def test_check_keys_tuple(self):
        keys = node.check_keys(('a', 'aa', 'aaa'))
        self.assertTrue(isinstance(keys, list))

    def test_check_keys_list(self):
        keys = node.check_keys(['a', 'aa', 'aaa'])
        self.assertTrue(isinstance(keys, list))

    def test_check_keys_none(self):
        self.assertRaises(TypeError, node.check_keys, None)

    def test_check_keys_int(self):
        self.assertRaises(TypeError, node.check_keys, 1)

    def test_check_keys_string(self):
        keys = node.check_keys('a.aa.aaa')
        self.assertTrue(isinstance(keys, list))

    def test_get_by_none(self):
        s, subkeys = self.r.find_closest(None)
        self.assertEqual(self.r, s)
        self.assertEqual(0, len(subkeys))

    def test_get_by_empty(self):
        s, subkeys = self.r.find_closest('')
        self.assertEqual(self.r, s)
        self.assertEqual(0, len(subkeys))

    def test_get_by_string(self):
        s, subkeys = self.r.find_closest('a.ab.aba.abaa')
        self.assertEqual(self.abaa, s)

    def test_get_by_sequence(self):
        s, subkeys = self.r.find_closest(('a', 'ab', 'aba', 'abaa'))
        self.assertEqual(self.abaa, s)

    def test_get_by_list(self):
        s, subkeys = self.r.find_closest(['a', 'ab', 'aba', 'abaa'])
        self.assertEqual(self.abaa, s)
        self.assertEqual(0, len(subkeys))

    def test_get_by_string_missing(self):
        s, subkeys = self.r.find_closest('a.ab.aba.abaa.abaaa')
        self.assertEqual(self.abaa, s)
        self.assertEqual(1, len(subkeys))

    def test_str(self):
        self.assertIsNotNone(str(self.r))

    def test_repr(self):
        self.assertIsNotNone(repr(self.r))

    def test_ancestors_root(self):
        l = [n for n in self.r.ancestors()]
        self.assertEqual(0, len(l))

    def test_ancestors_abaa(self):
        l = [n for n in self.abaa.ancestors()]
        self.assertEqual(4, len(l))

    def test_self_ancestors_root(self):
        l = [n for n in self.r.self_and_ancestors()]
        self.assertEqual(1, len(l))

    def test_self_ancestors_abaa(self):
        l = [n for n in self.abaa.self_and_ancestors()]
        self.assertEqual(5, len(l))

    def test_descendents(self):
        l = [n for n in self.r.descendents()]
        self.assertEqual(10, len(l))

    def test_prefix(self):
        l = [n for n in self.r.prefix()]
        self.assertEqual(11, len(l))
        self.assertEqual(self.r, l[0])

    def test_postfix(self):
        l = [n for n in self.r.postfix()]
        self.assertEqual(11, len(l))
        self.assertEqual(self.r, l[-1])

    def test_has_node_true(self):
        self.assertTrue(self.r.has_node(['a', 'ab', 'aba', 'abaa']))

    def test_has_node_false(self):
        self.assertFalse(self.r.has_node(['a', 'ab', 'aba', 'abaa', 'xxxxx']))

    def test_get_node_true(self):
        self.assertEqual(self.abaa, self.r.get_node(['a', 'ab', 'aba', 'abaa']))

    def test_get_node_false(self):
        self.assertIsNone(self.r.get_node(['a', 'ab', 'aba', 'abaa', 'xxxxx']))

    def test_find_closest_empty(self):
        n = node(key='')
        parent, subkeys = n.find_closest(['a', 'aa', 'aaa'])
        self.assertEqual(n, parent)
        self.assertEqual(3, len(subkeys))

    def test_create(self):
        n = node(key='')
        a = n.create_child(['a'])
        self.assertEqual('a', a.key)
        self.assertEqual(n, a.parent)

        aa = n.create_child(['a', 'aa'])
        self.assertEqual('aa', aa.key)
        self.assertEqual(a, aa.parent)

    def test_has_node(self):
        # setup
        n = node(key='')
        a = n.create_child(['a'])
        aa = n.create_child(['a', 'aa'])

        self.assertTrue(n.has_node(['a']))
        self.assertTrue(n.has_node(['a', 'aa']))
        self.assertFalse(n.has_node(['a', 'aa', 'aaa']))

    def test_has_node(self):
        # setup
        n = node(key='')
        a = n.create_child(['a'])
        aa = n.create_child(['a', 'aa'])

        self.assertEqual(a, n.get_node(['a']))
        self.assertEqual(aa, n.get_node(['a', 'aa']))
        self.assertIsNone(n.get_node(['a', 'aa', 'aaa']))

    def test_delete(self):
        # setup
        n = node(key='')
        a = n.create_child(['a'])
        aa = n.create_child(['a', 'aa'])

        self.assertIsNone(n.delete_child(['a', 'aa', 'aaa']))
        self.assertEqual(aa, n.delete_child(['a', 'aa']))
        self.assertIsNone(n.delete_child(['a', 'aa']))
        self.assertEqual(a, n.delete_child(['a']))
        self.assertIsNone(n.delete_child(['a']))













class perm(object):
    def __init__(self, gid=(), uid=None):
        # Convert gid to a sequence if it is not already.
        if not is_sequence_or_set(gid):
            gid = (gid, )

        self.gid = set(gid)
        self.uid = uid

    def has_permission(self, perm=None):
        if not perm and (self.gid or self.uid):
            return False

        if self.gid and not self.gid.intersection(perm.gid):
            return False

        if self.uid and self.uid != perm.uid:
            return False

        return True

    def __str__(self):
        return str(self.gid) + ':' + str(self.uid)

    def __repr__(self):
        return 'gid=' + str(self.gid) + ', pid=' + str(self.uid)

class TestPerm(unittest.TestCase):
    def test_init_gid_string(self):
        p = perm(gid='gid0')
        self.assertEqual(set(('gid0', )), p.gid)

    def test_init_gid_seq_string_1(self):
        p = perm(gid=('gid0', ))
        self.assertEqual(set(('gid0', )), p.gid)

    def test_init_gid_seq_string_2(self):
        p = perm(gid=('gid0', 'gid1'))
        self.assertEqual(set(('gid0', 'gid1')), p.gid)

    def test_init_gid_int(self):
        p = perm(gid=1)
        self.assertEqual(set((1, )), p.gid)

    def test_init_gid_seq_int_1(self):
        p = perm(gid=(1, ))
        self.assertEqual(set((1, )), p.gid)

    def test_init_uid_string(self):
        p = perm(uid='uid0')
        self.assertEqual('uid0', p.uid)

    def test_init_uid_int(self):
        p = perm(uid=1)
        self.assertEqual(1, p.uid)

    def test_init_both_string(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertEqual(set(('gid0', )), p.gid)
        self.assertEqual('uid0', p.uid)

    def test_has_perm_none(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertFalse(p.has_permission())

    def test_has_perm_empty(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertFalse(p.has_permission(perm()))

    def test_has_perm_both(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertTrue(p.has_permission(perm(gid='gid0', uid='uid0')))

    def test_has_perm_both2(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertTrue(p.has_permission(perm(gid=('gid0', 'gid1'), uid='uid0')))

    def test_has_perm_gid_only(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertFalse(p.has_permission(perm(gid='gid0')))

    def test_has_perm_uid_only(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertFalse(p.has_permission(perm(uid='uid0')))

    def test_str(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertIsNotNone(str(p))

    def test_repr(self):
        p = perm(gid='gid0', uid='uid0')
        self.assertIsNotNone(repr(p))

class endpoint(object):
    def __init__(self, perm):
        self.perm = perm

    def __call__(self, publishment):
        logger.info('notified ' + str(self.perm) + ' of content ' + str(publishment))

    def __str__(self):
        return str(self.perm)

    def __repr__(self):
        return 'perm=' + repr(self.perm)

class TestEndpoint(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, endpoint)

    def test_call(self):
        e = endpoint(perm=())
        p = publishment(content='content')
        e(p)

class topic(object):
    def __init__(self, name, from_perm=perm(), to_perm=perm()):
        self.name = name
        self.from_perm = from_perm
        self.to_perm = to_perm

    def can_publish(self, from_perm=perm()):
        return self.from_perm.has_permission(from_perm)

    def can_subscribe(self, to_perm=perm()):
        return self.to_perm.has_permission(to_perm)

    def __str__(self):
        return str(self.name) + '-' + str(self.from_perm) + '-' + str(self.to_perm)

    def __repr__(self):
        return 'name=' + str(self.name) + ', from=' + str(self.from_perm) + ', to=' + str(self.to_perm)

class TestTopic(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, topic)

    def test_str(self):
        t = topic('name')
        self.assertIsNotNone(str(t))

    def test_repr(self):
        t = topic('name')
        self.assertIsNotNone(repr(t))

class publishment(object):
    def __init__(self, content, ttl=None):
        self.content = content
        self.ttl = ttl

    def __str__(self):
        return str(self.content)

    def __repr__(self):
        return 'content=' + str(self.content) + ', ttl=' + str(self.ttl)

class TestPublishment(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, publishment)

    def test_init_content(self):
        p = publishment(content='content')
        self.assertIsNotNone(p.content)

    def test_init_both(self):
        p = publishment(content='content', ttl=12)
        self.assertIsNotNone(p.content)
        self.assertEqual(12, p.ttl)

    def test_str(self):
        p = publishment(content='content', ttl=12)
        self.assertIsNotNone(str(p))

    def test_repr(self):
        p = publishment(content='content', ttl=12)
        self.assertIsNotNone(repr(p))

class topic_node(object):
    def __init__(self, topic):
        self.topic = topic
        self.publishments = []
        self.subscriptions = []

    def publish(self, publishment, endpoint):
        if not self.topic.can_publish(endpoint.perm):
            raise PermissionError('publish failed, topic perm=' + str(self.topic.from_perm) + ', endpoint perm=' + str(endpoint.perm))

        self.publishments.append(publishment)

        for subscription in self.subscriptions:
            self.notify(subscription, publishment)

    def subscribe(self, endpoint):
        if not self.topic.can_subscribe(endpoint.perm):
            raise PermissionError('subscribe failed, topic perm=' + str(self.topic.to_perm) + ', endpoint perm=' + str(endpoint.perm))

        self.subscriptions.append(endpoint)
        self.notify(endpoint, self.latest())

    def read(self, endpoint):
        if not self.topic.can_subscribe(endpoint.perm):
            raise PermissionError('read failed, topic perm=' + str(self.topic.to_perm) + ', endpoint perm=' + str(endpoint.perm))

        return self.latest()

    def latest(self):
        if not self.publishments:
            return None

        return self.publishments[-1]

    def notify(self, subscription, publishment):
        if not self.topic.to_perm.has_permission(subscription.perm):
            raise PermissionError('notify failed, topic perm=' + str(self.topic.to_perm) + ', endpoint perm=' + str(subscription.perm))

        subscription(publishment)

    def __str__(self):
        return 'topic=' + str(self.topic)

    def __repr__(self):
        return 'topic=' + str(self.topic) + ', subscriptions=' + ', publishments='

class TestTopicNode(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, topic_node)

class provider(object):
    def __init__(self):
        self.endpoints = set()
        self.root = node('<root>')

    def create_endpoint(self, endpoint):
        self.endpoints.add(endpoint)

    def delete_endpoint(self, endpoint):
        self.endpoints.remove(endpoint)

    def get_node(self, topic):
        return self.root.get_node(topic.name)

    def create_node(self, topic):
        return self.root.create_child(topic.name)

    def delete_node(self, topic):
        return self.root.delete_child(topic.name)

class TestProvider(unittest.TestCase):
    def setUp(self):
        self.s = provider()

        self.mike = endpoint(perm(gid='user', uid='mike'))
        self.s.create_endpoint(self.mike)

        self.chloe = endpoint(perm(gid='admin', uid='chloe'))
        self.s.create_endpoint(self.chloe)

        self.ta = topic('status', perm(gid='admin'), perm(gid='admin'))
        self.blog = topic('blog', perm(gid='user', uid='mike'))

    def test_create_node(self):
        s = provider()
        s.create_node(topic('a.aa.aaa'))
        s.create_node(topic('b.ba.baa.baaa'))
        s.create_node(topic('b.ba.bab.baba'))
        l = [n for n in s.root.prefix()]
        self.assertEqual(10, len(l))

    def test_delete_endpoint(self):
        self.s.delete_endpoint(self.mike)
        self.s.delete_endpoint(self.chloe)

class service(object):
    def __init__(self):
        self.provider = provider()

    def register(self, endpoint):
        self.provider.create_endpoint(endpoint)

    def unregister(self, endpoint):
        self.provider.delete_endpoint(endpoint)
        # TODO: Remove subscriptions

    def publish(self, topic, publishment, endpoint):
        n = self.provider.create_node(topic)
        if not n.data:
            n.data = topic_node(topic)

        return n.data.publish(publishment, endpoint)

    def subscribe(self, topic, endpoint):
        n = self.provider.create_node(topic)
        if not n.data:
            n.data = topic_node(topic)

        return n.data.subscribe(endpoint)

    def read(self, topic, endpoint):
        n = self.provider.get_node(topic)
        if not n:
            return None

        return n.data.read(endpoint)

class TestService(unittest.TestCase):
    def setUp(self):
        self.s = service()

        self.mike = endpoint(perm(gid='user', uid='mike'))
        self.s.register(self.mike)

        self.chloe = endpoint(perm(gid='admin', uid='chloe'))
        self.s.register(self.chloe)

        self.ta = topic('status', perm(gid='admin'), perm(gid='admin'))
        self.blog = topic('blog', perm(gid='user', uid='mike'))

    def test_prepublish(self):
        self.s.publish(topic=self.blog, publishment=publishment('version0'), endpoint=self.mike)

    def test_subscribe(self):
        self.assertRaises(PermissionError, subscription=self.s.subscribe, topic=self.ta, endpoint=self.mike)
        self.s.subscribe(topic=self.ta, endpoint=self.chloe)
        self.s.subscribe(topic=self.blog, endpoint=self.mike)
        self.s.subscribe(topic=self.blog, endpoint=self.chloe)

    def test_publish(self):
        self.assertRaises(PermissionError, self.s.publish, topic=self.ta, publishment=publishment('fails'), endpoint=self.mike)
        self.s.publish(topic=self.ta, publishment=publishment('admin version1'), endpoint=self.chloe)
        self.s.publish(topic=self.blog, publishment=publishment('version1'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publishment=publishment('version2'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publishment=publishment('version3'), endpoint=self.mike)
        self.assertRaises(PermissionError, self.s.publish, topic=self.blog, publishment=publishment('fails'), endpoint=self.chloe)

    def test_read(self):
        self.s.publish(topic=self.ta, publishment=publishment('admin version1'), endpoint=self.chloe)
        self.s.publish(topic=self.blog, publishment=publishment('version1'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publishment=publishment('version2'), endpoint=self.mike)
        self.s.publish(topic=self.blog, publishment=publishment('version3'), endpoint=self.mike)

        self.assertRaises(PermissionError, self.s.read, topic=self.ta, endpoint=self.mike)
        self.assertEqual('admin version1', self.s.read(topic=self.ta, endpoint=self.chloe).content)
        self.assertEqual('version3', self.s.read(topic=self.blog, endpoint=self.mike).content)
        self.assertEqual('version3', self.s.read(topic=self.blog, endpoint=self.chloe).content)

    def test_delete_endpoint(self):
        self.s.unregister(self.mike)
        self.s.unregister(self.chloe)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('pubsub')

    s = service()

    mike = endpoint(perm=perm(gid='user', uid='mike'))
    s.register(mike)
    print('endpoint', str(mike))

    chloe = endpoint(perm=perm(gid='admin', uid='chloe'))
    s.register(chloe)
    print('endpoint', str(chloe))

    blog = topic(name='blog', from_perm=perm(gid='user', uid='mike'))
    print('topic', str(blog))

    print('pre-publish')
    s.publish(topic=blog, publishment=publishment('version0'), endpoint=mike)

    print('subscribe')
    s.subscribe(topic=blog, endpoint=mike)
    s.subscribe(topic=blog, endpoint=chloe)

    print('publish')
    s.publish(topic=blog, publishment=publishment('version1'), endpoint=mike)
    s.publish(topic=blog, publishment=publishment('version2'), endpoint=mike)
    s.publish(topic=blog, publishment=publishment('version3'), endpoint=mike)

    logger.setLevel(level=logging.WARNING)
    unittest.main()


"""
hierarchy of nodes (nested subscriptions)
manage endpoint lifetimes
should pubs just have one gid?

endpoint
  perm

topic
  name
  to
  from

publishment
  content
  ttl

topic_node
  topic
  publishments
  subscriptions

service
  endpoints
  nodes
"""