import boto3

from service_analyzers import iam
from service_analyzers import ec2
from service_analyzers import s3
from service_analyzers import vpc

# accessKeyId = ''
# secretAccessKey = ''
# session = boto3.Session(aws_access_key_id=accessKeyId, aws_secret_access_key=secretAccessKey)

clients = {}
clients['iam'] = boto3.client('iam')
# clients['ec2'] = session.client('ec2')
# clients['s3'] = session.client('s3')
# clients['vpc'] = session.client('vpc')

iam.run_all_checks(clients['iam'])
iam.analyze_policies(clients['iam'])

print(clients['iam'])