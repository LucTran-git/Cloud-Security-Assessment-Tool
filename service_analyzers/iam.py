import boto3
import json
import datetime
import botocore
import os

# def iam_client:
#     def __init(self):

# iam = boto3.client('iam')
# client = boto3.client('accessanalyzer')

def list(iam):
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

