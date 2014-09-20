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
        logger.info('notified ' + str(publishment))

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

class node(object):
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

class TestNode(unittest.TestCase):
    def test_init_error(self):
        self.assertRaises(TypeError, node)

class xnode(object):
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        if self.parent:
            self.parent.add_child(self)
        self.children = {}

    def delete(self):
        if self.parent:
            self.parent.remove_child(self)

    def add_child(self, child):
        self.children[child.name] = child

    def remove_child(self, child):
        del self.children[child.name]

    def up(self, list=None):
        if list is None:
            list = []

        list.append(self)
        if self.parent:
            return self.parent.up(list)
        else:
            return list

    def down(self, list=None, prefix=True):
        if list is None:
            list = []

        if prefix:
            list.append(self)

        for name, child in self.children.items():
            child.down(list)

        if not prefix:
            list.append(self)

        return list

    def get_descendent(self, names, separator='.'):
        if not names:
            return self

        if isinstance(names, str):
            # If the name is specified as a string, break into a sequence.
            names = names.split(separator)
        elif hasattr(names, '__iter__') and not hasattr(names, 'pop'):
            # If name is iter-able, but not pop-able, then convert it into a list.
            names = list(names)

        return self.__get_descendent__(names)

    def __get_descendent__(self, names):
        if not names:
            return self

        name = names.pop(0)

        return self.children[name].__get_descendent__(names)

    def __str__(self):
        return 'name=' + str(self.name)

    def __repr__(self):
        return 'name=' + repr(self.name) + ', parent=' + repr(self.parent) + ', children=' + repr(self.children)

class TestXNode(unittest.TestCase):
    def setUp(self):
        self.r = xnode('r')
        self.a = xnode('a', self.r)
        self.aa = xnode('aa', self.a)
        self.ab = xnode('ab', self.a)
        self.aba = xnode('aba', self.ab)
        self.abaa = xnode('abaa', self.aba)
        self.ac = xnode('ac', self.a)
        self.b = xnode('b', self.r)
        self.c = xnode('c', self.r)
        self.ca = xnode('ca', self.c)
        self.cb = xnode('cb', self.c)

    def test_init_none(self):
        self.assertRaises(TypeError, xnode)

    def test_init_name(self):
        n = xnode('name')
        self.assertEqual('name', n.name)
        self.assertIsNone(n.parent)
        self.assertEqual(0, len(n.children))

    def test_init_add(self):
        n = xnode('')
        n.add_child(xnode(''))
        self.assertEqual(1, len(n.children))

    def test_init_remove(self):
        n = xnode('')
        c = xnode('')
        n.add_child(c)
        n.remove_child(c)
        self.assertEqual(0, len(n.children))

    def test_up(self):
        l = self.abaa.up()
        self.assertEqual(5, len(l))
        self.assertEqual(self.abaa, l[0])
        self.assertEqual(self.r, l[-1])

    def test_down_prefix(self):
        l = self.r.down()
        self.assertEqual(11, len(l))
        self.assertEqual(self.r, l[0])

    def test_down_postfix(self):
        l = self.r.down(prefix=False)
        self.assertEqual(11, len(l))
        self.assertEqual(self.r, l[-1])

    def test_get_by_none(self):
        n = self.r.get_descendent(None)
        self.assertEqual(self.r, n)

    def test_get_by_empty(self):
        n = self.r.get_descendent('')
        self.assertEqual(self.r, n)

    def test_get_by_string(self):
        n = self.r.get_descendent('a.ab.aba.abaa')
        self.assertEqual(self.abaa, n)

    def test_get_by_sequence(self):
        n = self.r.get_descendent(('a', 'ab', 'aba', 'abaa'))
        self.assertEqual(self.abaa, n)

    def test_get_by_list(self):
        n = self.r.get_descendent(['a', 'ab', 'aba', 'abaa'])
        self.assertEqual(self.abaa, n)

    def test_str(self):
        self.assertIsNotNone(str(self.r))

    def test_repr(self):
        self.assertIsNotNone(repr(self.r))

class store(object):
    def __init__(self):
        self.endpoints = set()
        self.nodes = {}

    def create_endpoint(self, endpoint):
        self.endpoints.add(endpoint)

    def delete_endpoint(self, endpoint):
        # TODO: remove subscriptions
        self.endpoints.remove(endpoint)

    def create_node(self, topic):
        self.nodes[topic] = node(topic)

    def delete_node(self, topic):
        # TODO: remove subscriptions
#        del topic self.nodes
        pass

    def get_node(self, topic):
        return self.nodes[topic]

    def get_or_create_node(self, topic):
        if not topic in self.nodes:
            self.create_node(topic)

        return self.get_node(topic)

class service(object):
    def __init__(self):
        self.endpoints = set()
        self.nodes = {}

    def create_endpoint(self, endpoint):
        self.endpoints.add(endpoint)

    def delete_endpoint(self, endpoint):
        # TODO: remove subscriptions
        self.endpoints.remove(endpoint)

    def create_node(self, topic):
        self.nodes[topic] = node(topic)

    def delete_node(self, topic):
        # TODO: remove subscriptions
#        del topic self.nodes
        pass

    def get_node(self, topic):
        return self.nodes[topic]

    def get_or_create_node(self, topic):
        if not topic in self.nodes:
            self.create_node(topic)

        return self.get_node(topic)

    def publish(self, topic, publishment, endpoint):
        n = self.get_or_create_node(topic)
        return n.publish(publishment, endpoint)

    def subscribe(self, topic, endpoint):
        n = self.get_or_create_node(topic)
        return n.subscribe(endpoint)

    def read(self, topic, endpoint):
        n = self.get_node(topic)
        return n.read(endpoint)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    ea = endpoint(perm(gid='user', uid='mike'))
    eb = endpoint(perm(gid='admin', uid='chloe'))
    print('ea', str(ea))
    print('eb', str(eb))

    n = service()
    n.create_endpoint(ea)
    n.create_endpoint(eb)

    ta = topic('admin_stuff', perm(gid='admin'), perm(gid='admin'))
    tb = topic('mikes_stuff', perm(gid='user', uid='mike'))
    print('ta', str(ta))
    print('tb', str(tb))

    print('pre-publish')
    n.publish(topic=tb, publishment=publishment('version0'), endpoint=ea)

    print('subscribe')
    try:
        n.subscribe(topic=ta, endpoint=ea)
    except PermissionError:
        pass
    n.subscribe(topic=ta, endpoint=eb)

    n.subscribe(topic=tb, endpoint=ea)
    n.subscribe(topic=tb, endpoint=eb)

    print('publish')
    try:
        n.publish(topic=ta, publishment=publishment('fails'), endpoint=ea)
    except PermissionError:
        pass
    n.publish(topic=ta, publishment=publishment('admin version1'), endpoint=eb)

    n.publish(topic=tb, publishment=publishment('version1'), endpoint=ea)
    n.publish(topic=tb, publishment=publishment('version2'), endpoint=ea)
    n.publish(topic=tb, publishment=publishment('version3'), endpoint=ea)

    try:
        n.publish(topic=tb, publishment=publishment('fails'), endpoint=eb)
    except PermissionError:
        pass

    print('read')
    try:
        n.read(topic=ta, endpoint=ea)
    except PermissionError:
        pass
    print('ub reads na=' + str(n.read(topic=ta, endpoint=eb)))
    print('ua reads nb=' + str(n.read(topic=tb, endpoint=ea)))
    print('ub reads nb=' + str(n.read(topic=tb, endpoint=eb)))


    n.delete_endpoint(ea)
    n.delete_endpoint(eb)

    logger.setLevel(level=logging.WARNING)
    unittest.main()


"""
hierarchy of nodes (nested subscriptions)
manage endpoint lifetimes


endpoint
  perm

topic
  name
  to
  from

publishment
  content
  ttl




node
  topic
  publishments
  subscriptions

service
  endpoints
  nodes

"""