#!/usr/bin/env python3
import logging

from perm import Perm
from endpoint import Endpoint
from publication import Publication
from service import Service

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('pubsub')

    p = Perm(gid=('admin', 'user'))
    perms = p.to_perms()
    s = Service(perms)

    mike = Endpoint(perm=Perm(gid='user', uid='mike'))
    s.register(mike)
    print('endpoint', str(mike))

    chloe = Endpoint(perm=Perm(gid=('admin', 'user'), uid='chloe'))
    s.register(chloe)
    print('endpoint', str(chloe))

    blog = 'blog'
    print('topic', str(blog))

    print('pre-publish')
    s.publish(topic=blog, publication=Publication('version0'), endpoint=mike)

    print('subscribe')
    s.subscribe(topic=blog, endpoint=mike)
    s.subscribe(topic=blog, endpoint=chloe)

    print('publish')
    s.publish(topic=blog, publication=Publication('version1'), endpoint=mike)
    s.publish(topic=blog, publication=Publication('version2'), endpoint=mike)
    s.publish(topic=blog, publication=Publication('version3'), endpoint=mike)

"""
implement proper str and repr
fix function cases
hierarchy of nodes (nested subscriptions)
manage endpoint lifetimes
should pubs just have one gid?
support ancestor recursion for notify?

perm

perms
  dict of perm (c,d,r,w)

endpoint
  perms

publication
  content
  ttl

tnode
  node
  publications
  subscriptions

provider
  endpoints
  tnodes

service
  provider
"""