#!/usr/bin/env python3
import logging
import unittest
import itertools

from key import Key
from perm import Perm

class Node(object):
    """
        Uses the following objects:
          - A key object that must implement an __inter__() function that returns each
            subkey in order from top to bottom.
          - A permission object that must implement a __call__() function that takes
            another permission to validate.  It returns True if the permission check
            passes, False otherwise.
    """
    def __create__(self, key, parent=None, perms=None, data=None, *args, **kwargs):
        return Node(key=key, parent=parent, perms=perms, args=args, kwargs=kwargs)

    def __init__(self, key, parent=None, perms=None, data=None, *args, **kwargs):
        """
        Create a node.  If a parent is specified, link the parent and child nodes.
        """
        self.key = key

        self.parent = parent
        if self.parent:
            self.parent.children[self.key] = self

        self.children = {}

        self.perms = perms
        n = self.parent
        while self.perms is None and n:
            self.perms = n.perms
            n = n.parent

        self.data = data

        self.logger = logging.getLogger('Node')

    def has_permission(self, op, perms):
        """
        If perm has permission to perform operation, op, on this node, then return True;
        otherwise return False
        """

        # This is a special case.  If the caller did not provide permissions, then
        # permissions are not required.
        if perms is None:
            return True

        # If the node does not have permissions, then permissions are not required.
        if self.perms is None:
            return True

        # Both sets of permissions must have a permission for the operation.
        try:
            thisperm = self.perms[op]
            thatperm = perms[op]
        except KeyError:
            self.logger.info('failed to find permissions for op=' + str(op))
            return False

        return thisperm(thatperm)

    def check_permission(self, op, perms):
        """
        Throw an exception if perm does not have enough permission to perform the
        operation, op, on this node.
        """
        if not self.has_permission(op, perms):
            raise PermissionError('check permission failed: op=' + str(op) + ', required=' + str(self.perms) + ', provided=' + str(perms))

    def __delete__(self):
        """
        Delete this node.  If this node has a parent, unlink the parent and child nodes.
        """
        if self.parent:
            del self.parent.children[self.key]

    def create_child(self, keys, perms=None, *args, **kwargs):
        """
        Create a child node using the specified key.
        """
        self.check_permission('c', perms)

        if not keys:
            return self

        # Find the closest existing node.
        n, subkeys = self.find_closest_child(keys, perms)

        # Create new nodes.
        for subkey in subkeys:
            n = self.__create__(key=subkey, parent=n, perms=perms, args=args, kwargs=kwargs)

        # Return the new child.
        return n

    def delete_child(self, keys, perms=None):
        """
        Delete the child node specified by the key if it exists.
        Return the deleted node if it exists; otherwise return None.
        """
        self.check_permission('d', perms)

        n = self.get_node(keys)
        if not n:
            return None

        n.__delete__()
        return n

    def find_closest_child(self, keys, perms=None):
        """
        Return the child node specified by the key.
        If the node does not exist, return its closest ancestor and the remaining subkeys.
        """
        if not keys:
            return self, ()

        keys = list(keys)

        try:
            n = self
            while len(keys):
                n.check_permission('r', perms)

                subkey = keys[0]
                n = n.children[subkey]
                keys.pop(0)
        except KeyError:
            pass

        return n, keys

    def has_node(self, keys, perms=None):
        """
        If the child node specified by the key exists, return True; otherwise return False.
        """
        parent, subkeys = self.find_closest_child(keys, perms)
        return not len(subkeys)

    def get_node(self, keys, perms=None):
        """
        Return the child node specified by the key if it exists; otherwise return None.
        """
        parent, subkeys = self.find_closest_child(keys, perms)
        if not len(subkeys):
            return parent

        return None

    def ancestors(self, perms=None):
        """
        Return an iterator for this nodes ancestors (parent, grandparent, etc.).
        """
        self.check_permission('r', perms)

        if self.parent:
            yield from self.parent.self_and_ancestors(perms)

    def self_and_ancestors(self, perms=None):
        """
        Return an iterator for this node and its ancestors (self, parent, grandparent, etc.).
        """
        self.check_permission('r', perms)

        yield self
        yield from self.ancestors(perms)

    def descendants(self, perms=None):
        """
        Return an iterator for this nodes descendants (children, grandchildren, etc.).
        """
        self.check_permission('r', perms)

        for key, child in self.children.items():
            yield from child.prefix(perms)

    def prefix(self, perms=None):
        """
        Return an iterator for this node and its descendants (children, grandchildren, etc.)
        with the parent before the children (prefix).
        """
        self.check_permission('r', perms)

        yield self
        yield from self.descendants(perms)

    def postfix(self, perms=None):
        """
        Return an iterator for this node and its descendants (children, grandchildren, etc.)
        with the parent after the children (postfix).
        """
        self.check_permission('r', perms)

        yield from self.descendants(perms)
        yield self

    def read(self, perms=None):
        """
        Return the node's data.
        """
        self.check_permission('r', perms)
        return self.data

    def write(self, value, perms=None):
        """
        Set the node's data.
        """
        self.check_permission('w', perms)
        self.data = value

    def __str__(self):
        return 'key=' + str(self.key)

    def __repr__(self):
        return 'key=' + repr(self.key) + \
            ', parent=' + repr(self.parent) + \
            ', children=' + repr(self.children) + \
            ', perms=' + repr(self.perms) + \
            ', data=' + repr(self.data)

class TestNode(unittest.TestCase):
    def setUp(self):
        self.r = Node('r')
        self.a = Node('a', self.r)
        self.aa = Node('aa', self.a)
        self.ab = Node('ab', self.a)
        self.aba = Node('aba', self.ab)
        self.abaa = Node('abaa', self.aba)
        self.ac = Node('ac', self.a)
        self.b = Node('b', self.r)
        self.c = Node('c', self.r)
        self.ca = Node('ca', self.c)
        self.cb = Node('cb', self.c)

    def test_init_none(self):
        self.assertRaises(TypeError, Node)

    def test_init_key(self):
        s = Node('key')
        self.assertEqual('key', s.key)
        self.assertIsNone(s.parent)
        self.assertEqual(0, len(s.children))

    def test_get_by_none(self):
        s, subkeys = self.r.find_closest_child(None)
        self.assertEqual(self.r, s)
        self.assertEqual(0, len(subkeys))

    def test_get_by_empty(self):
        s, subkeys = self.r.find_closest_child('')
        self.assertEqual(self.r, s)
        self.assertEqual(0, len(subkeys))

    def test_get_by_string(self):
        s, subkeys = self.r.find_closest_child(Key('a.ab.aba.abaa'))
        self.assertEqual(self.abaa, s)

    def test_get_by_sequence(self):
        s, subkeys = self.r.find_closest_child(('a', 'ab', 'aba', 'abaa'))
        self.assertEqual(self.abaa, s)

    def test_get_by_list(self):
        s, subkeys = self.r.find_closest_child(['a', 'ab', 'aba', 'abaa'])
        self.assertEqual(self.abaa, s)
        self.assertEqual(0, len(subkeys))

    def test_get_by_string_missing(self):
        s, subkeys = self.r.find_closest_child(Key('a.ab.aba.abaa.abaaa'))
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

    def test_descendants(self):
        l = [n for n in self.r.descendants()]
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

    def test_find_closest_child_empty(self):
        n = Node(key='')
        parent, subkeys = n.find_closest_child(['a', 'aa', 'aaa'])
        self.assertEqual(n, parent)
        self.assertEqual(3, len(subkeys))

    def test_create(self):
        n = Node(key='')
        a = n.create_child(['a'])
        self.assertEqual('a', a.key)
        self.assertEqual(n, a.parent)

        aa = n.create_child(['a', 'aa'])
        self.assertEqual('aa', aa.key)
        self.assertEqual(a, aa.parent)

    def test_has_node(self):
        # setup
        n = Node(key='')
        a = n.create_child(['a'])
        aa = n.create_child(['a', 'aa'])

        self.assertTrue(n.has_node(['a']))
        self.assertTrue(n.has_node(['a', 'aa']))
        self.assertFalse(n.has_node(['a', 'aa', 'aaa']))

    def test_has_node(self):
        # setup
        n = Node(key='')
        a = n.create_child(['a'])
        aa = n.create_child(['a', 'aa'])

        self.assertEqual(a, n.get_node(['a']))
        self.assertEqual(aa, n.get_node(['a', 'aa']))
        self.assertIsNone(n.get_node(['a', 'aa', 'aaa']))

    def test_delete(self):
        # setup
        n = Node(key='')
        a = n.create_child(['a'])
        aa = n.create_child(['a', 'aa'])

        self.assertIsNone(n.delete_child(['a', 'aa', 'aaa']))
        self.assertEqual(aa, n.delete_child(['a', 'aa']))
        self.assertIsNone(n.delete_child(['a', 'aa']))
        self.assertEqual(a, n.delete_child(['a']))
        self.assertIsNone(n.delete_child(['a']))

    def test_get_ancestor_perms_none(self):
        a = Node(key='a', perms=None)
        aa = Node(key='aa', parent=a)
        self.assertIs(a.perms, aa.perms)
        self.assertIsNone(aa.perms)

    def test_get_ancestor_perms_empty(self):
        a = Node(key='a', perms={})
        aa = Node(key='aa', parent=a)
        self.assertIs(a.perms, aa.perms)

    def test_get_ancestor_perms_notempty(self):
        a = Node(key='a', perms={'r': True})
        aa = Node(key='aa', parent=a)
        self.assertIs(a.perms, aa.perms)

    def test_get_ancestor_perms_missing(self):
        a = Node(key='a')
        aa = Node(key='aa', parent=a)
        self.assertIs(a.perms, aa.perms)

    def test_get_ancestor_perms_parent(self):
        a = Node(key='a', perms={})
        aa = Node(key='aa', parent=a, perms={})
        aaa = Node(key='aaa', parent=aa)
        self.assertIs(aa.perms, aaa.perms)
        self.assertIsNot(a.perms, aaa.perms)

    def test_get_ancestor_perms_grandparent(self):
        a = Node(key='a', perms={})
        aa = Node(key='aa', parent=a)
        aaa = Node(key='aaa', parent=aa)
        self.assertIs(a.perms, aaa.perms)
        self.assertIs(aa.perms, aaa.perms)

    def test_has_permission_none(self):
        a = Node(key='a', perms=None)
        self.assertTrue(a.has_permission(op='r', perms=Perm()))

    def test_has_permission_no_op(self):
        a = Node(key='a', perms={})
        self.assertFalse(a.has_permission(op='r', perms=Perm()))

    def test_has_permission_fail_empty(self):
        a = Node(key='a', perms={'r': Perm(gid='good')})
        self.assertFalse(a.has_permission(op='r', perms={'r' : Perm()}))

    def test_has_permission_fail(self):
        a = Node(key='a', perms={'r': Perm(gid='good')})
        self.assertFalse(a.has_permission(op='r', perms={'r' : Perm(gid='bad')}))

    def test_has_permission_success(self):
        a = Node(key='a', perms={'r': Perm(gid='good')})
        self.assertTrue(a.has_permission(op='r', perms={'r' : Perm(gid='good')}))

    def test_has_permission_ignore(self):
        a = Node(key='a', perms={'r': Perm(gid='good')})
        self.assertTrue(a.has_permission(op='r', perms=None))

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
