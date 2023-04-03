import boto3
import json
import datetime
import botocore
import os

from .abstract import * 
# Note the use of * in importing; this way,
# abstract functions are called as iam.func_name()
# instead of iam.abstract.func_name() 

def analyze_policies(iam):
    '''This is a docstring. Use this to give an explanation of your method when you hover over it in the IDE
    
    You can make a docstring by putting a multi-line comment immediately below a function def
    
    Also works for files when importing them, like I did with abstract.py'''
    return NotImplementedError
    response = iam.list_policies(
        #Scope='All'|'AWS'|'Local',
        #OnlyAttached=True,  # Only check policies in use, b/c those are the relevant ones
                            # Could use False for more thorough check, in case customer might change policies 
        #PathPrefix='string',
        #PolicyUsageFilter='PermissionsPolicy'|'PermissionsBoundary',
        #Marker='string',   # Only used to paginate results; set it to value of the 'Marker' element in a previous
                            # response to continue where you left off
        #MaxItems=123
    )
    for policy in response['Policies']:
        print(policy)

def write_analysis_to_file():
    '''Write errors (and maybe other data), and recommendations to a log file'''
    return NotImplementedError

#def run_all_checks(iam):
    print('Running all checks for iam...')
    return NotImplementedError



