import boto3
import json
import botocore

import matplotlib.pyplot as plt 

from service_analyzers import iam
from service_analyzers import ec2vpc
from service_analyzers import s3


ec2 = boto3.client('ec2')

all_warnings = {}

# open session with the account
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

print('Populating service clients...')
clients = {}

###---------------------------------------------------IAM SECTION----------------------------------------------------------------------
print('Acquiring iam client...')
clients['iam'] = session.client('iam')

###---------------------------------------------------EC2 SECTION----------------------------------------------------------------------
#1.since an account can have multiple instances in different regions, get a list of regions where the service is available
print('Acquiring ec2 available regions...')
ec2_regions = []
for regionName in session.get_available_regions('ec2'):
    try:
        print('Getting region...')
        ec2_clientTMP = session.client('ec2', region_name=regionName)
        ec2_clientTMP.describe_instances()
        ec2_regions.append(regionName)
    except botocore.exceptions.ClientError as e:
        print(f"region unavailable: {regionName}: {str(e)}")
        pass

#2.create a list of service "client" objects for each region for the service and obtain a description of those EC2 instances

print('Creating list of ec2 clients...')
ec2_clients_List = []

for i in range(len(ec2_regions)):
    ec2_clients_List.append(session.client('ec2', ec2_regions[i]))

clients['ec2'] = ec2_clients_List

###---------------------------------------------------------------------------------------------------------------------------------------

clients['s3'] = session.client('s3')
clients['vpc'] = session.client('vpc')

###-------------------------------------------------- PERFORM CHECKS -----------------------------------------------------------

iam.check_IAM_EC2_configurations(clients['ec2'])
iam.analyze_local_managed_policies(clients['iam'])  
ec2vpc.check_EC2_VPC_configurations(ec2)

# all_warnings contains services, which contain warning_categories, which contain warning_instances:
# all_warnings 
#  |
#  services
#   |
#   warning_categories
#    |
#    warning instances

for service, client in clients.items():

    if service == 'IAM':
        all_warnings['IAM'] = iam.get_policy_warnings()
        all_warnings['IAM'].update(iam.get_EC2_VPC_warnings())


### UNIQUE WARNINGS PER SERVICE ###
x = []
y = []

for service, wc_dict in all_warnings.items():
    x.append(service)
    y.append(len(wc_dict))

fig, ax = plt.subplots()
ax.bar(x=x, height=y)

plt.xlabel('Services') 
plt.ylabel('# of types of warnings') 
plt.title('# of types of warnings per service') 
plt.savefig('logs/types_of_warnings_per_service.png') 
plt.show() 
# btw, u have to savefig before show. after show is called, a new (blank) figure is created 

### TOTAL WARNINGS PER SERVICE ###
x = []
y = []

for service, wc_dict in all_warnings.items():
    w_cnt = 0
    for _, w_list in wc_dict.items():
        w_cnt += len(w_list)
    x.append(service)
    y.append(w_cnt)

fig, ax = plt.subplots()
ax.bar(x=x, height=y)

plt.xlabel('Services') 
plt.ylabel("total # of warnings") 
plt.title('total # of warnings per service') 
plt.savefig('logs/total_warnings_per_service.png')
plt.show() 

print(json.dumps(all_warnings, indent=4))
