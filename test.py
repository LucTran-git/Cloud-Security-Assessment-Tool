import boto3
import json

from service_analyzers import iam
from service_analyzers import ec2
from service_analyzers import s3
from service_analyzers import vpc

with open('Credentials.json', 'r') as credsFile:
    credsData = json.load(credsFile)

    if (not credsData['AWS']['access_key_id'] or not credsData['AWS']['secret_access_key']):
        credsData['AWS']['access_key_id'] = input("Please enter Access Key ID:")
        credsData['AWS']['secret_access_key'] = input("Please enter Secret Access Key:")

        with open('Credentials.json', 'w') as credsFileOut:    
            json.dump(credsData, credsFileOut, indent=4)

accessKeyId = credsData['AWS']['access_key_id']
secretAccessKey = credsData['AWS']['secret_access_key']

session = boto3.Session(aws_access_key_id=accessKeyId, aws_secret_access_key=secretAccessKey)

clients = {}
clients['iam'] = session.client('iam')
# clients['ec2'] = session.client('ec2')
# clients['s3'] = session.client('s3')
# clients['vpc'] = session.client('vpc')

#iam.run_all_checks(clients['iam'])
iam.analyze_local_managed_policies(clients['iam'])

#print(clients['iam'])