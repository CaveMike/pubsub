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

class xnode(object):
    def __init__(self, key, parent=None):
        self.key = key
        self.parent = parent
        if self.parent:
            self.parent.add_child(self)
        self.children = {}

    def delete(self):
        if self.parent:
            self.parent.remove_child(self)

    def add_child(self, child):
        self.children[child.key] = child

    def remove_child(self, child):
        del self.children[child.key]

    def find_closest(self, keys):
        if not keys:
            return self, ()

        try:
            n = self
            while len(keys):
                subkey = keys[0]
                n = n.children[subkey]
                keys.pop(0)
        except KeyError:
            pass

        return n, keys

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

        for key, child in self.children.items():
            child.down(list)

        if not prefix:
            list.append(self)

        return list

    def __str__(self):
        return 'key=' + str(self.key)

    def __repr__(self):
        return 'key=' + repr(self.key) + ', parent=' + repr(self.parent) + ', children=' + repr(self.children)

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

    def test_init_key(self):
        n = xnode('key')
        self.assertEqual('key', n.key)
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
        n, subkeys = self.r.find_closest(None)
        self.assertEqual(self.r, n)
        self.assertEqual(0, len(subkeys))

    def test_get_by_empty(self):
        n, subkeys = self.r.find_closest('')
        self.assertEqual(self.r, n)
        self.assertEqual(0, len(subkeys))

#    def test_get_by_string(self):
#        n = self.r.find_closest('a.ab.aba.abaa')
#        self.assertEqual(self.abaa, n)

#    def test_get_by_sequence(self):
#        n = self.r.find_closest(('a', 'ab', 'aba', 'abaa'))
#        self.assertEqual(self.abaa, n)

    def test_get_by_list(self):
        n, subkeys = self.r.find_closest(['a', 'ab', 'aba', 'abaa'])
        self.assertEqual(self.abaa, n)
        self.assertEqual(0, len(subkeys))

#    def test_get_by_string_missing(self):
#        self.assertRaises(KeyError, self.r.find_closest, 'a.ab.aba.abaa.abaaa')

    def test_str(self):
        self.assertIsNotNone(str(self.r))

    def test_repr(self):
        self.assertIsNotNone(repr(self.r))

class xnodes(object):
    def __init__(self, separator='.'):
        self.root = node('<root>')
        self.separator = separator

    def check_keys(self, keys):
        if isinstance(keys, str):
            return keys.split(self.separator)
        elif not hasattr(keys, '__iter__'):
            raise TypeError('invalid keys')
        elif not hasattr(keys, 'pop'):
            # If keys is iter-able, but not pop-able, then convert it into a list.
            return list(keys)

        return keys

    def find_closest(self, keys):
        keys = self.check_keys(keys)
        return self.root.find_closest(keys)

    def has_node(self, keys):
        parent, subkeys = self.find_closest(keys)
        return not len(subkeys)

    def get_node(self, keys):
        parent, subkeys = self.find_closest(keys)
        if not len(subkeys):
            return parent

        return None

    def create_node(self, keys):
        if not keys:
            return self.root

        keys = self.check_keys(keys)

        # Find the closest existing node.
        n, subkeys = self.find_closest(keys)

        # Create new nodes.
        for subkey in keys:
            n = xnode(subkey, n)

        return n

    def delete_node(self, keys):
        n = self.get_node(keys)
        if not n:
            return None

        n.delete()

        return n

class TestXNodes(unittest.TestCase):
    def setUp(self):
        self.x = xnodes()

    def test_check_keys_tuple(self):
        keys = self.x.check_keys(('a', 'aa', 'aaa'))
        self.assertTrue(isinstance(keys, list))

    def test_check_keys_list(self):
        keys = self.x.check_keys(['a', 'aa', 'aaa'])
        self.assertTrue(isinstance(keys, list))

    def test_check_keys_none(self):
        self.assertRaises(TypeError, self.x.check_keys, None)

    def test_check_keys_int(self):
        self.assertRaises(TypeError, self.x.check_keys, 1)

    def test_check_keys_string(self):
        keys = self.x.check_keys('a.aa.aaa')
        self.assertTrue(isinstance(keys, list))

    def test_find_closest_empty(self):
        parent, subkeys = self.x.find_closest(['a', 'aa', 'aaa'])
        self.assertEqual(self.x.root, parent)
        self.assertEqual(3, len(subkeys))

    def test_create(self):
        a = self.x.create_node(['a'])
        self.assertEqual('a', a.key)
        self.assertEqual(self.x.root, a.parent)

        aa = self.x.create_node(['a', 'aa'])
        self.assertEqual('aa', aa.key)
        self.assertEqual(a, aa.parent)

    def test_has_node(self):
        # setup
        a = self.x.create_node(['a'])
        aa = self.x.create_node(['a', 'aa'])

        self.assertTrue(self.x.has_node(['a']))
        self.assertTrue(self.x.has_node(['a', 'aa']))
        self.assertFalse(self.x.has_node(['a', 'aa', 'aaa']))

    def test_has_node(self):
        # setup
        a = self.x.create_node(['a'])
        aa = self.x.create_node(['a', 'aa'])

        self.assertEqual(a, self.x.get_node(['a']))
        self.assertEqual(aa, self.x.get_node(['a', 'aa']))
        self.assertIsNone(self.x.get_node(['a', 'aa', 'aaa']))

    def test_delete(self):
        # setup
        a = self.x.create_node(['a'])
        aa = self.x.create_node(['a', 'aa'])

        self.assertIsNone(self.x.delete_node(['a', 'aa', 'aaa']))
        self.assertEqual(aa, self.x.delete_node(['a', 'aa']))
        self.assertIsNone(self.x.delete_node(['a', 'aa']))
        self.assertEqual(a, self.x.delete_node(['a']))
        self.assertIsNone(self.x.delete_node(['a']))















class node(xnode):
    def __init__(self, topic, parent=None):
        xnode.__init__(self, key=topic, parent=parent)
        self.publishments = []
        self.subscriptions = []

    def publish(self, publishment, endpoint):
        if not self.key.can_publish(endpoint.perm):
            raise PermissionError('publish failed, topic perm=' + str(self.key.from_perm) + ', endpoint perm=' + str(endpoint.perm))

        self.publishments.append(publishment)

        for subscription in self.subscriptions:
            self.notify(subscription, publishment)

    def subscribe(self, endpoint):
        if not self.key.can_subscribe(endpoint.perm):
            raise PermissionError('subscribe failed, topic perm=' + str(self.key.to_perm) + ', endpoint perm=' + str(endpoint.perm))

        self.subscriptions.append(endpoint)
        self.notify(endpoint, self.latest())

    def read(self, endpoint):
        if not self.key.can_subscribe(endpoint.perm):
            raise PermissionError('read failed, topic perm=' + str(self.key.to_perm) + ', endpoint perm=' + str(endpoint.perm))

        return self.latest()

    def latest(self):
        if not self.publishments:
            return None

        return self.publishments[-1]

    def notify(self, subscription, publishment):
        if not self.key.to_perm.has_permission(subscription.perm):
            raise PermissionError('notify failed, topic perm=' + str(self.key.to_perm) + ', endpoint perm=' + str(subscription.perm))

        subscription(publishment)

    def __str__(self):
        return 'topic=' + str(self.key)

    def __repr__(self):
        return 'topic=' + str(self.key) + ', subscriptions=' + ', publishments='

class service(object):
    def __init__(self):
        self.endpoints = set()
        self.root = node('<root>')
        self.separator = '.'

    def create_endpoint(self, endpoint):
        self.endpoints.add(endpoint)

    def delete_endpoint(self, endpoint):
        # TODO: remove subscriptions
        self.endpoints.remove(endpoint)

    def create_node(self, topic):
        if not topic:
            return self.root

        if isinstance(topic, str):
            # If the key is specified as a string, break into a sequence.
            topic = topic.split(self.separator)
        elif hasattr(topic, '__iter__') and not hasattr(topic, 'pop'):
            # If key is iter-able, but not pop-able, then convert it into a list.
            topic = list(topic)

        return self.__create_node__(topic)

    def __create_node__(self, topic):
        n = self.root

        # Find the lowest node that is already created.
        try:
            while True:
                subtopic = topic[0]
                n = n.children[subtopic]
                topic.pop(0)
        except KeyError:
            pass

        # Create any new nodes.
        for subtopic in topic:
            n = node(subtopic, n)

    def delete_node(self, topic):
        # TODO: remove subscriptions
        # TODO: remove node
        pass

    def has_node(self, topic):
        try:
            n = self.root
            while True:
                subtopic = topic[0]
                n = n.children[subtopic]
                topic.pop(0)
        except KeyError:
            return False

        return True

    def get_node(self, topic):
        return self.root.get_descendent(topic)

    def get_or_create_node(self, topic):
        try:
            return self.get_node(topic)
        except KeyError:
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


    def get_descendent(self, names, separator='.'):
        if not names:
            return self

        if isinstance(names, str):
            # If the key is specified as a string, break into a sequence.
            names = names.split(separator)
        elif hasattr(names, '__iter__') and not hasattr(names, 'pop'):
            # If key is iter-able, but not pop-able, then convert it into a list.
            names = list(names)

        return self.__get_descendent__(names)




class TestService(unittest.TestCase):
    def test_create(self):
        s = service()
        s.__create_node__(['a', 'aa', 'aaa'])
        s.__create_node__(['a', 'aa', 'aab'])
        s.__create_node__(['b', 'ba', 'baa'])
        s.create_node('b.ba.baa.baaa')
        l = s.root.down()
        for n in l:
            print(n.key)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    """
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
    """
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