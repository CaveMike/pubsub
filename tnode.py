#!/usr/bin/env python3
import logging
import unittest

from node import Node

class TopicNode(Node):
    def __create__(self, key, parent=None, perms=None, data=None, *args, **kwargs):
        return TopicNode(key=key, parent=parent, perms=perms, data=data, args=args, kwargs=kwargs)

    def __init__(self, key, parent=None, perms=None, data=None, *args, **kwargs):
        super(TopicNode, self).__init__(key=key, parent=parent, perms=perms, data=data, args=args, kwargs=kwargs)
        self.publications = []
        self.subscriptions = []

    def publish(self, publication, perms=None):
        self.check_permission('w', perms)

        self.publications.append(publication)

        for subscription in self.subscriptions:
            self.notify(subscription, publication)

    def subscribe(self, endpoint, perms=None):
        self.check_permission('r', perms)

        self.subscriptions.append(endpoint)
        self.notify(endpoint, self.latest())

    def read(self, perms=None):
        self.check_permission('r', perms)

        return self.latest()

    def latest(self, perms=None):
        self.check_permission('r', perms)

        if not self.publications:
            return None

        return self.publications[-1]

    def notify(self, subscription, publication):
        # TODO: apply to-filter
        subscription(publication)

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
