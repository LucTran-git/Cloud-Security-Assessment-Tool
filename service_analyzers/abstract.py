'''
Abstract functions, i.e.
List of functions that every service analyzer file should have

To import functions into your service analyzer file, use:

from .abstract import *

This way, functions are added to the same namespace, i.e.
functions are called as iam.my_func() instead of iam.abstract.my_func()
'''

def run_all_checks(client):
    print('asdf')
    raise NotImplementedError