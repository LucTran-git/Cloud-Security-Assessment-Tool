import boto3
import json
import datetime
import botocore
import os


# json encoder used for outputting service data into json file
class jsonHelper(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return super().default(obj)




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
AccountservicesList = accountSession.get_available_services()

#The demonstration below is used to show how to connect to services and get their configurations, We'll use EC2 as an example:

#1.since an account can have multiple instances in different regions, get a list of regions where the service is available
ec2_regions = []
for regionName in accountSession.get_available_regions('ec2'):
    try:
        ec2_clientTMP = accountSession.client('ec2', region_name=regionName)
        ec2_clientTMP.describe_instances()
        ec2_regions.append(regionName)
    except botocore.exceptions.ClientError as e:
        print(f"region unavailable: {regionName}: {str(e)}")

#2.create a list of service "client" objects for each region for the service and obtain a description of those EC2 instances
ec2_clients_List = []
ec2_description_list = []
for i in range(len(ec2_regions)):
    ec2_clients_List.append(accountSession.client('ec2', ec2_regions[i]))
    ec2_description_list.append(ec2_clients_List[i].describe_instances())

#3. output info about the service for all regions allowed
if not os.path.exists('EC2/'):
    os.makedirs('EC2/')
    
for i in range(len(ec2_description_list)):
    with open('EC2/'+ ec2_regions[i] +'.json', 'w+') as outPutJsonFile:
        json.dump(ec2_description_list[i], outPutJsonFile, indent=4, cls=jsonHelper)


        
 




