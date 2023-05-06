import boto3
import json
import datetime
import botocore
import os

from service_analyzers import iam
from service_analyzers import ec2
from service_analyzers import s3
from service_analyzers import vpc
from service_analyzers import CloudTrail


#Check if Creds Credentials.json has access keys and if it doesn't, ask them for it and store values in Credentials.json
with open('Credentials.json', 'r') as credsFile:
    credsData = json.load(credsFile)

    if (not credsData['AWS']['access_key_id'] or not credsData['AWS']['secret_access_key']):
        credsData['AWS']['access_key_id'] = input("Please enter Access Key ID:")
        credsData['AWS']['secret_access_key'] = input("Please enter Secret Access Key:")

        with open('Credentials.json', 'w') as credsFileOut:    
            json.dump(credsData, credsFileOut, indent=4)


accessKeyId = credsData['AWS']['access_key_id']
secretAccessKey = credsData['AWS']['secret_access_key']

# Create a session using the specified credentials and obtain all the services running on the account
accountSession = boto3.Session(aws_access_key_id=accessKeyId, aws_secret_access_key=secretAccessKey)
#AccountservicesList = accountSession.get_available_services()

# Calling scanning scripts

ec2 = boto3.client('ec2')                                         # EC2 - VPC
ec2.check_EC2_VPC_configurations(ec2)

iam.analyze_local_managed_policies(accountSession.client('iam'))  # IAM
iam.IAM_EC2_starter(accountSession)                               # IAM - EC2


CloudTrail.starting_function(accountSession)                      # CloudTrail

s3.starting_function(accountSession)                              # S3









