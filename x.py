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
    SEPARATOR = '.'

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

    def get_descendent(self, names):
        if not names:
            return self

        if isinstance(names, str):
            # If the name is specified as a string, break into a sequence.
            names = names.split(xnode.SEPARATOR)
        elif hasattr(names, '__iter__') and not hasattr(names, 'pop'):
            # If name is iter-able, but not pop-able, then convert it into a list.
            names = list(names)

        name = names.pop(0)

        return self.children[name].get_descendent(names)

class TestXNode(unittest.TestCase):
    def test_up(self):
        r = xnode('r')
        a = xnode('a', r)
        aa = xnode('aa', a)
        ab = xnode('ab', a)
        aba = xnode('aba', ab)
        abaa = xnode('abaa', aba)
        ac = xnode('ac', a)
        b = xnode('b', r)
        c = xnode('c', r)
        ca = xnode('ca', c)
        cb = xnode('cb', c)

        n = r.get_descendent(None)
        print('n', n.name)

        print(r.get_descendent('').name)

        print(r.get_descendent('c.cb').name)

        n = r.get_descendent('a.ab.aba.abaa')
        print('n', n.name)

        n = r.get_descendent(['a', 'ab', 'aba', 'abaa'])
        print('n', n.name)

        n = r.get_descendent(('a', 'ab', 'aba', 'abaa'))
        print('n', n.name)

        print('')
        print('----up----')
        list = abaa.up()
        for l in list:
            print(l.name)

        print('----down----')
        list = r.down(prefix=True)
        for l in list:
            print(l.name)

        print('----down----')
        list = r.down(prefix=False)
        for l in list:
            print(l.name)

        print('----down----')
        ab.delete()
        list = r.down()
        for l in list:
            print(l.name)


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