#!/usr/bin/env python3
import logging
import unittest
from carbon.helpers import is_sequence_or_set

class Perm(object):
    TYPES = ('c', 'd', 'r', 'w')

    def __init__(self, gid=(), uid=None):
        # Convert gid to a sequence if it is not already.
        if not is_sequence_or_set(gid):
            gid = (gid, )

        self.gid = set(gid)
        self.uid = uid

        self.logger = logging.getLogger('Perm')

    def to_perms(self):
        perms = {}
        for t in Perm.TYPES:
            perms[t] = self
        return perms

    def __call__(self, perm=None):
        self.logger.debug('self=' + str(self) + ', them=' + str(perm))
        if not perm:
            if self.gid or self.uid:
                self.logger.info('gid or uid required, but not provided')
                return False
            else:
                self.logger.debug('gid and uid not required')
                return True

        if self.gid:
            if self.gid.intersection(perm.gid):
                self.logger.debug('matched gid: gid=' + str(self.gid.intersection(perm.gid)))
                return True
            self.logger.info('failed to match gid: required=' + str(self.gid) + ', provided=' + str(perm.gid))

        if self.uid:
            if self.uid == perm.uid:
                return True
            self.logger.info('failed to match uid: required=' + str(self.uid) + ', provided=' + str(perm.uid))

        return False

    def __str__(self):
        return str(','.join(self.gid)) + ':' + (str(self.uid) if self.uid else '')

    def __repr__(self):
        return 'gid=' + str(self.gid) + ', uid=' + str(self.uid)

class TestPerm(unittest.TestCase):
    def test_init_gid_string(self):
        p = Perm(gid='gid0')
        self.assertEqual(set(('gid0', )), p.gid)

    def test_init_gid_seq_string_1(self):
        p = Perm(gid=('gid0', ))
        self.assertEqual(set(('gid0', )), p.gid)

    def test_init_gid_seq_string_2(self):
        p = Perm(gid=('gid0', 'gid1'))
        self.assertEqual(set(('gid0', 'gid1')), p.gid)

    def test_init_gid_int(self):
        p = Perm(gid=1)
        self.assertEqual(set((1, )), p.gid)

    def test_init_gid_seq_int_1(self):
        p = Perm(gid=(1, ))
        self.assertEqual(set((1, )), p.gid)

    def test_init_uid_string(self):
        p = Perm(uid='uid0')
        self.assertEqual('uid0', p.uid)

    def test_init_uid_int(self):
        p = Perm(uid=1)
        self.assertEqual(1, p.uid)

    def test_init_both_string(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertEqual(set(('gid0', )), p.gid)
        self.assertEqual('uid0', p.uid)

    def test_has_perm_none(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertFalse(p())

    def test_has_perm_empty(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertFalse(p(Perm()))

    def test_has_perm_both(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertTrue(p(Perm(gid='gid0', uid='uid0')))

    def test_has_perm_both2(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertTrue(p(Perm(gid=('gid0', 'gid1'), uid='uid0')))

    def test_has_perm_gid_only(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertTrue(p(Perm(gid='gid0')))

    def test_has_perm_uid_only(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertTrue(p(Perm(uid='uid0')))

    def test_str(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertIsNotNone(str(p))

    def test_repr(self):
        p = Perm(gid='gid0', uid='uid0')
        self.assertIsNotNone(repr(p))

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
