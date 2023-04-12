import boto3
import json
import datetime
import botocore
import os
import re
import ipaddress

from .abstract import * 
# Note the use of * in importing; this way,
# abstract functions are called as iam.func_name()
# instead of iam.abstract.func_name() 



# Warnings are a dict of (list of dicts), as follows:
# { 'policy_name' : [{'warning' : 'text', 'explanation' : 'text', 'recommendation' : 'text'}, ...] }
# We separate the warning info in this way to make it easier to format the report in different ways e.g. txt vs csv

# Policy checks
passrole_actions = ['*','iam:*','iam:PassRole']
policy_docs = {} # These are the JSON files that define policies
policy_warnings = {} # dict of (list of dicts) 

#created another dict since ec2 checks output differs from IAM due the multi-ragion feature. feel free to change this if you want
EC2_VPC_checks = {} # dict of (list of dicts) 

###---------------------------------------------------EC2 SECTION----------------------------------------------------------------------

#helper used to print contents of policy_warnings

#helper used to write info to policy_warnings
def EC2_VPC_checks_writer(policy_name, error_dict):
    if policy_name not in EC2_VPC_checks:
        # policy_docs[policy_name] = []
        EC2_VPC_checks[policy_name] = []


    EC2_VPC_checks[policy_name].append(error_dict)

#function used to analyze IAM/Security groups related info for EC2/VPC
def check_IAM_EC2_configurations(ec2_clients):
    
    def check_IAM_role(ec2_client):

        #get instances ids
        initial_response = ec2_client.describe_instances()
        instanceIds = [instance['InstanceId'] for reservation in initial_response['Reservations'] for instance in reservation['Instances']]
         
        if len(instanceIds) < 1:
            return

        #Describe the IAM instance profile associations for the instances
        response = ec2_client.describe_iam_instance_profile_associations(
            Filters=[{'Name': 'instance-id', 'Values': instanceIds}]
        )

        #case where none of the instances are using IAM roles
        if len(response['IamInstanceProfileAssociations']) < 1:
            for i in instanceIds:
                dict = {"warning": "IAM role not attached to EC2 instance ID: " + i
                        ,"explanation": "EC2 instances should use an IAM role instead of hard-coded AWS credentials"
                        , "recommendation": "Attach an IAM role to the EC2 instance using the EC2 console or the AWS CLI"}
                
                EC2_VPC_checks_writer("IAM Role Association", dict)

            return
            

        #other cases
        for association in response['IamInstanceProfileAssociations']:
            if not association['IamInstanceProfile']['Arn'].startswith('arn:aws:iam::'):

                dict = {"warning": "IAM role not attached to EC2 instance ID: " + association['InstanceId']
                        ,"explanation": "EC2 instances should use an IAM role instead of hard-coded AWS credentials"
                        , "recommendation": "Attach an IAM role to the EC2 instance using the EC2 console or the AWS CLI"}
                
                EC2_VPC_checks_writer("IAM Role Association", dict)
    
    def check_VPC_public_to_private_communication (ec2_client):

        
      
        #get ec2 instances ids
        initial_response = ec2_client.describe_instances()
        ec2_instanceIds = [instance['InstanceId'] for reservation in initial_response['Reservations'] for instance in reservation['Instances']]
         
        if len(ec2_instanceIds) < 1:
            return

        #get all the vpc IDs in the ec2 client
        vpc_ids = []
        
        for ec2_id in ec2_instanceIds:
            response = ec2_client.describe_instances(InstanceIds=[ec2_id])
            vpc_id = response['Reservations'][0]['Instances'][0]['VpcId']

            if vpc_id not in vpc_ids:
                vpc_ids.append(vpc_id)


        for vpc_id in vpc_ids:
            #start of check
            public_subnets = []
            private_subnets = []
            
            #get the subnets in the VPC
            subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
            for subnet in subnets:
                if subnet['MapPublicIpOnLaunch']:
                    public_subnets.append(subnet['SubnetId'])
                else:
                    private_subnets.append(subnet['SubnetId'])

            #Get the route tables in the VPC
            route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['RouteTables']

            #Check each VPC peering connection
            peering_connections = ec2_client.describe_vpc_peering_connections(Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc_id]}])['VpcPeeringConnections']
            for peering_connection in peering_connections:
                #Check if the peering connection is between a public and private subnet
                if peering_connection['RequesterVpcInfo']['VpcId'] == vpc_id:
                    peer_vpc_id = peering_connection['AccepterVpcInfo']['VpcId']
                    peer_subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [peer_vpc_id]}])['Subnets']
                    peer_public_subnets = [subnet['SubnetId'] for subnet in peer_subnets if subnet['MapPublicIpOnLaunch']]
                    if not peer_public_subnets:
                        continue  #Peering connection doesn't have a public subnet on the other side

                    #Check if any public subnet route tables have a route to a private subnet through this peering connection
                    for route_table in route_tables:
                        for route in route_table['Routes']:
                            if route['DestinationCidrBlock'] in [f"{subnet['CidrBlock']}" for subnet in private_subnets]:
                                if route['GatewayId'] == peering_connection['VpcPeeringConnectionId'] and route_table['Associations'][0]['SubnetId'] in public_subnets:
                                    
                                    #a public subnet route tables have a route to a private subnet
                                    dict = {
                                        "warning": "Communication between public and private VPC tiers is enabled in VPC ID: " + vpc_id,
                                        "explanation": "Enabling communication between public and private VPC tiers can create a security vulnerability where unauthorized users can access private resources.",
                                        "recommendation": "Disable communication between public and private VPC tiers or ensure that appropriate security measures are in place such as security groups and network ACLs."
                                    }

                                    EC2_VPC_checks_writer("VPC public to private communication", dict)

    def check_EC2_unused_security_groups(ec2_client):
        #Get a list of all instances
        instances = ec2_client.describe_instances()

        #Create a set of all security group IDs associated with instances
        instance_security_groups = set()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for group in instance['SecurityGroups']:
                    instance_security_groups.add(group['GroupId'])

        #Get a list of all security groups
        security_groups = ec2_client.describe_security_groups()

        #Create a set of all security group IDs
        all_security_groups = set()
        for group in security_groups['SecurityGroups']:
            all_security_groups.add(group['GroupId'])

        #Identify unused security groups
        unused_security_groups = all_security_groups - instance_security_groups

        for group_id in unused_security_groups:
            dict = {
            "warning": "Unused EC2 security group ID: " + group_id,
            "explanation": "Unused EC2 security groups Increase the difficulty of managing security groups efficiently",
            "recommendation": "Regularly monitor and remove unused security groups to reduce the attack surface of your infrastructure."
            }

            EC2_VPC_checks_writer("Unused EC2 Security Group", dict)  

    def check_VPC_unknown_crossaccount_access(ec2_client):





        endpoints = ec2_client.describe_vpc_endpoints()

        #iterate through endpoints and check their policies
        for endpoint in endpoints['VpcEndpoints']:
            endpoint_id = endpoint['VpcEndpointId']
            
            #check if the endpoint has a policy document
            if 'PolicyDocument' in endpoint and endpoint['PolicyDocument']:
                policy_document = json.loads(endpoint['PolicyDocument'])
                policies = policy_document['Statement']
                
                #check for "*" wildcard usage
                for policy in policies:
                    if policy['Effect'] == 'Allow' and policy['Principal'] == '*':
                        
                            dict = {
                            "warning": "Amazon VPC endpoint allows wildcard character: " + endpoint_id ,
                            "explanation": "Endpoint policy allows any AWS account, IAM user, role, federated user, or AWS service granted access to perform any action on any resource",
                            "recommendation": "Ensure that VPC endpoints are properly secured by restricting access to only authorized accounts or resources."
                            }

                            EC2_VPC_checks_writer("VPC endpoint cross-account access", dict)  

    def check_EC2_security_groups_traffic_rules(ec2_client):

        #get all security groups
        response = ec2_client.describe_security_groups()

        #Loop through the security groups and check if any allow all inbound traffic
        for group in response['SecurityGroups']:

            #Check if the security group has a rule that allows all inbound traffic
            for rule in group['IpPermissions']:
                if 'IpRanges' in rule and len(rule['IpRanges']) == 1:
                    if rule['IpRanges'][0]['CidrIp'] == '0.0.0.0/0':

                        warning = {
                            "warning": f"Security group {group['GroupId']} allows all inbound traffic on some or all ports",
                            "explanation": "Allowing all inbound traffic on some or all ports may cause security vulnerabilities",
                            "recommendation": "Update the security group's inbound rules to limit traffic to only necessary IP addresses and ports"
                        }

                        EC2_VPC_checks_writer("Allow All Inbound Traffic", warning)


            #Check if the security group has a rule that allows all outbound traffic
            for rule in group['IpPermissionsEgress']:
                if rule['IpProtocol'] == '-1' and '0.0.0.0/0' in [cidr['CidrIp'] for cidr in rule['IpRanges']]:
                    warning = {
                            "warning": f"Security group {group['GroupId']} allows outbound traffic on all ports",
                            "explanation": "Allowing outbound traffic on all ports may cause security vulnerabilities",
                            "recommendation": "Update the security group's outbound rules to limit traffic to only necessary ports"
                        }

                    EC2_VPC_checks_writer("Allow All Outbound Ports", warning)

            #check for rule allowing inbound traffci from RFC-1918 CIDRs
            for rule in group['IpPermissions']:
                if 'FromPort' in rule and 'ToPort' in rule and 'IpRanges' in rule:
                    for ip_range in rule['IpRanges']:
                        cidr = ipaddress.ip_network(ip_range['CidrIp'])
                        if cidr.is_private:
                            warning = {
                                "warning": f"Security group {group['GroupId']} allows inbound traffic from RFC-1918 CIDRs",
                                "explanation": "Allowing inbound traffic from RFC-1918 CIDRs may cause security vulnerabilities",
                                "recommendation": "Update the security group's inbound rules to block inbound traffic from RFC-1918 CIDRs"
                            }

                            EC2_VPC_checks_writer("Allow RFC-1918 CIDRs Inbound Traffic", warning)

    def check_EC2_security_groups_launch_by_wizard(ec2_client):

        response = ec2_client.describe_security_groups()

        for group in response['SecurityGroups']:
            if 'launch-wizard' in group['GroupName']:
                #Check if the security group is in use
                instances = ec2_client.describe_instances(Filters=[
                    {'Name': 'instance.group-id', 'Values': [group['GroupId']]}
                ])
                if len(instances['Reservations']) > 0:
                    dict = {
                                "warning": f"Security group {group['GroupId']} in use was created by the launch wizard",
                                "explanation": "Security groups created by the launch wizard may cause vulnerabilities due to their low level of configuration",
                                "recommendation": "Review and modify the security group settings or create a separate security group"
                            }

                    EC2_VPC_checks_writer("Security group created by launch wizard ", dict)

    def check_EC2_security_groups_default(ec2_client):

        response = ec2_client.describe_security_groups()

        for group in response['SecurityGroups']:
            if 'default' in group['GroupName']:
                #Check if the security group is in use
                instances = ec2_client.describe_instances(Filters=[
                    {'Name': 'instance.group-id', 'Values': [group['GroupId']]}
                ])
                if len(instances['Reservations']) > 0:
                    dict = {
                                "warning": f"Security group {group['GroupId']} in use is a default security group",
                                "explanation": "default security groups may cause vulnerabilities due to their low level of configuration",
                                "recommendation": "Create a separate security group"
                            }

                    EC2_VPC_checks_writer("Default Security Group used", dict)


    for ec2_client in ec2_clients:
        check_IAM_role(ec2_client)
        check_VPC_public_to_private_communication(ec2_client)
        check_EC2_unused_security_groups(ec2_client)
        check_VPC_unknown_crossaccount_access(ec2_client)
        check_EC2_security_groups_traffic_rules(ec2_client)
        check_EC2_security_groups_launch_by_wizard(ec2_client)
        check_EC2_security_groups_default(ec2_client)

        #we can output the results using the following:
        """
        # Convert the dict to a JSON string with indentation
        json_str = json.dumps(EC2_VPC_checks, indent=4)

        # Write the JSON string to a file
        with open("my_file.json", "w") as f:
            f.write(json_str)   
        """     
        

# ---------------------------------------------------------------------------------------------------------------------------------------


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



