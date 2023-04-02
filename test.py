import boto3
import service_analyzers as sa

accessKeyId = ''
secretAccessKey = ''
session = boto3.Session(aws_access_key_id=accessKeyId, aws_secret_access_key=secretAccessKey)

iam = session.client('iam')

print(session)