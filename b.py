#!/usr/bin/python2

u = open('user.ldif', 'r').read()
for i in range (10000):
  n = u.replace('3', str(i))
  print(n)


