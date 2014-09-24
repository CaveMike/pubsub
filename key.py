#!/usr/bin/env python3
import logging
import unittest

class Key(object):
    SEPARATOR = '.'

    def __init__(self, value):
        if isinstance(value, str):
            # If it is a string, split into a list of substrings.
            self.value = value.split(Key.SEPARATOR)
        elif not hasattr(value, '__iter__'):
            # If it not iter-able, then this cannot be a key.
            raise TypeError('invalid type')
        else:
            self.value = value

    def __iter__(self):
        return self.value.__iter__()

    def __getitem__(self, index):
        return self.value.__getitem__(index)

    def __str__(self):
        return Key.SEPARATOR.join(self.value)

    def __repr__(self):
        return self.value.__repr__()

class TestKey(unittest.TestCase):
    def test_init_tuple(self):
        k = Key(('a', 'aa', 'aaa'))
        self.assertTrue(hasattr(k, '__iter__'))

    def test_init_list(self):
        k = Key(['a', 'aa', 'aaa'])
        self.assertTrue(hasattr(k, '__iter__'))

    def test_init_string(self):
        k = Key('a.aa.aaa')
        self.assertTrue(hasattr(k, '__iter__'))

    def test_init_none(self):
        self.assertRaises(TypeError, Key.__init__, None)

    def test_init_int(self):
        self.assertRaises(TypeError, Key.__init__, 1)

    def test_str(self):
        k = Key(('a', 'aa', 'aaa'))
        self.assertEqual('a.aa.aaa', str(k))

    def test_repr(self):
        k = Key(('a', 'aa', 'aaa'))
        self.assertEqual(repr(k.value), repr(k))

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
