import boto3
import json
import datetime
import botocore
import os
import re

from .abstract import * 
# Note the use of * in importing; this way,
# abstract functions are called as iam.func_name()
# instead of iam.abstract.func_name() 

policy_docs = {}
policy_warnings = {} # dict of (list of dicts) 
            # { 'policy_name' : [{'warning' : 'text', 'explanation' : 'text', 'recommendation' : 'text'}, ...] }
            # We separate the warning info in this way to make it easier to format the report in different ways e.g. txt vs csv

passrole_actions = ['*','iam:*','iam:PassRole']

def check_policy_passrole_overly_permissive(policy, policy_doc):
    """Check that policy does not allow PassRole to pass roles for any service.
    If it did, an IAM identity with this policy could grant extra permissions
    to any service, posing major security risk"""
    for stmt in policy_doc['Statement']:
        if stmt['Effect'] != 'Allow':
            continue

        passrole_overly_permissive = False
        for action in stmt['Action']:
            if action in passrole_actions:
                for resource in stmt['Resource']:
                    if resource == '*':
                        passrole_overly_permissive = True
                        break
        if passrole_overly_permissive == False:
            continue
        
        try:
            policy_warnings[policy['PolicyName']]
        except KeyError:
            policy_warnings[policy['PolicyName']] = []

        policy_warnings[policy['PolicyName']].append(
                    {
"Warning" : """
    iam:PassRole overly permissive
""",
"Explanation" : """
    Any IAM identity (i.e. users, groups, or roles) 
    with this policy can assign roles to an instance
    of any resource.

    As such, this policy can be exploited to grant
    unintended permissions to any resource.
    
    More info: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
""",
"Recommendation": """
    If you want iam:PassRole to be permitted:
    - Specify resource ARNs explicitly in 'Resource'
    - Add the iam:PassedToService condition key to the statement
    
    If you do not want iam:PassRole to be permitted:
    - Specify iam actions explicitly in 'Action'
"""
                    }
        )

def analyze_local_managed_policies(iam):
    '''Get and analyze policies'''
    print('Analyzing local managed policies...')
    response = iam.list_policies(
        Scope= 'Local', #'All'|'AWS'|'Local',
        OnlyAttached=True,  # Only check policies in use, b/c those are the relevant ones
                            # Could use False for more thorough check, in case customer might change policies 
        #PathPrefix='string',
        #PolicyUsageFilter='PermissionsPolicy'|'PermissionsBoundary',
        #Marker='string',   # Only used to paginate results; set it to value of the 'Marker' element in a previous
                            # response to continue where you left off
        #MaxItems=123
    )

    # Obtain policy info, and perform some single-policy checks while we're at it
    for policy in response['Policies']:
        response = iam.get_policy_version(
        PolicyArn=policy['Arn'],
        VersionId=policy['DefaultVersionId']
        )

        # Get policy doc (i.e. JSON file) of this specific policy
        policy_doc = response['PolicyVersion']['Document']
        # Add the policy doc to policy_docs dict
        policy_docs[policy['PolicyName']] = policy_doc

        # Do the checks we can do on single policies
        check_policy_passrole_overly_permissive(policy, policy_doc)
        filepath = write_analysis_to_file('txt')
    print(f'Analysis finished and written to {filepath}')

def write_analysis_to_file(file_format):
    '''Write warnings and recommendations to a log file\n
    Parameters: file format\n
    Returns: filepath of written file'''
    
    filepath = 'logs/iam_report.txt'
    if file_format == 'txt':
        with open(filepath, 'w') as file:
            for policy_name, warnings in policy_warnings.items():
                file.write(
f"""----- Policy Name: {policy_name} -----
{json.dumps(policy_docs[policy_name], indent=4)}
                        
""")
                for w in warnings:
                    for label, text in w.items():
                        file.write("| " + label + " |" + text)
    return filepath

def run_all_checks(iam):
    print('Running all checks for iam...')
    return NotImplementedError



