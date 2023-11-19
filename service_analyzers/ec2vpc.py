import boto3
from botocore.exceptions import ClientError
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

policy_docs = {}
policy_warnings = {} # dict of (list of dicts) 
            # { 'policy_name' : [{'warning' : 'text', 'explanation' : 'text', 'recommendation' : 'text'}, ...] }
            # We separate the warning info in this way to make it easier to format the report in different ways e.g. txt vs csv


###---------------------------------------------------EC2 & VPC SECTION----------------------------------------------------------------------

def check_EC2_VPC_configurations(ec2_clients):

    # Define the check_EC2_EBS_volumes function
    def check_EC2_EBS_volumes(region):
        warnings = []
        # Print the current check and region
        print(f"Checking EBS volumes in {region}...")
        # Check the current region in the EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every Elastic Block Store (EBS) volume in the current region
        response = ec2.describe_volumes()
        # Check if the volume is unencrypted
        for volume in response['Volumes']:
            # Create a dictionary with data about the unencrypted volume
            if 'Encrypted' in volume and not volume['Encrypted']:
                volume_data = {"VolumeId": volume['VolumeId'], "Encrypted": volume['Encrypted'], "Region": region}
                # Generate warning for each unencrypted EBS volume with explanation and recommendation
                warning = {"warning": f"Unencrypted EBS volume {volume['VolumeId']} in region {region}",
                            "explanation": "EBS volumes should be encrypted to make sure that no compromise and protect data confidentiality",
                            "recommendation": "Encrypt and secure the EBS volume by employing the EC2 console encryption or the AWS CLI"}
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("EC2 Unencrypted EBS volumes", warnings)

    # Define the check_ec2_ebs_backup function
    def check_ec2_ebs_backup(region):
        warnings = []
        # Print the current check and region
        print(f"Checking EBS backup in {region}...")
        # Check the current region in the EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every Elastic Compute Cloud (EC2) instances in the current region
        response = ec2.describe_instances()
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                # Check if instance has any Elastic Block Store (EBS) volumes
                if 'BlockDeviceMappings' in instance:
                    for volume in instance['BlockDeviceMappings']:
                        volume_id = volume['Ebs']['VolumeId']
                        # Check if EBS volume has backup enabled in the current region
                        ebs = boto3.client('ec2', region_name=region)
                        # Describes all the specified EBS snapshots available
                        ebs_response = ebs.describe_snapshots(
                            Filters=[{'Name': 'volume-id', 'Values': [volume_id]}])
                        if len(ebs_response['Snapshots']) == 0:
                            # Generate warning for every EBS volume with no backup (snapshots)
                            warning = {
                                "warning": f"EBS volume {volume_id} for EC2 instance {instance_id} in region {region} has no backup enabled",
                                "explanation": "Enable EBS volumes backups are critical and playing essential role to ensure data durability and availability",
                                "recommendation": "Enable EBS backups (snapshots) using the EC2 console or the AWS CLI"}
                            warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("EC2 EBS Backup", warnings)

    # Define the security check functions
    def check_open_ports(region):
        warnings = []
        # Print the current check and region
        print(f"Checking open ports in VPCs in {region}...")
        # Check the current region in the EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve all Virtual Private Clouds (VPCs) in the current region
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            # Describe security groups for the VPC
            security_groups = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['SecurityGroups']
            # Retrieve all the security groups in the current Virtual Private Cloud (VPC)
            for s_groups in security_groups:
                group_id = s_groups['GroupId']
                group_name = s_groups['GroupName']
                # Check inbound rules for the security group
                for ipPermissions in s_groups['IpPermissions']:
                    fromPort = ipPermissions.get('FromPort')
                    toPort = ipPermissions.get('ToPort')
                    ipProtocol = ipPermissions.get('IpProtocol')

                    # Check if the port is open to the internet
                    for ip_range in ipPermissions.get('IpRanges', []):
                        cidr_ip = ip_range['CidrIp']
                        if cidr_ip == '0.0.0.0/0':
                            # Generate warning for every open ports(s)
                            warning = {
                                "warning": f"Open port(s) found in security group {group_name} ({group_id}) of VPC {vpc_id} in region {region}",
                                "explanation": f"For security purposes, Port(s) {fromPort}-{toPort}/{ipProtocol} must not be open to the internet",
                                "recommendation": "Restrict and limit port(s) access to a trusted set of IP addresses"
                            }
                            warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Open Ports in VPCs", warnings)

    # Define the check_security_groups_ingress function
    def check_security_groups_ingress(region):
        warnings = []
        # Print the current check and region
        print(f"Checking security groups ingress in {region}...")
        # Check the current region in the EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about all Elastic Compute Cloud (EC2) security groups in the current region
        response = ec2.describe_security_groups()
        # Check if any security group has a wide open ingress rule
        for securityGroup in response['SecurityGroups']:
            for permission in securityGroup['IpPermissions']:
                if 'IpRanges' in permission and len(permission['IpRanges']) > 0 and \
                        permission['IpRanges'][0]['CidrIp'] == '0.0.0.0/0' and permission['FromPort'] == 0 and \
                        permission['IpProtocol'] == 'tcp':
                    # Generate warning for every security groups has a wide open ingress rule
                    warning = {
                        "warning": f"A security group with a wide open ingress rule found in {securityGroup['GroupId']} in region {region}",
                        "explanation": "Restrict access to open ingress rule in security groups to only the necessary ports",
                        "recommendation": "Revise the security group rules to restrict access to only the necessary ports"}
                    warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Wide Open Ingress Rule in Security Groups", warnings)

    # Define the check_EC2_public_ips function
    def check_EC2_public_ips(region):
        warnings = []
        # Print the current check and region
        print(f"Checking EC2 instances Public IPs in {region}...")
        # Check the current region in the EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about all Elastic Compute Cloud (EC2) instances in the current region
        response = ec2.describe_instances()
        # Check if the instance has a public IP address
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if 'PublicIpAddress' in instance:
                    # Generate warning for all public IPs in the EC2
                    warning = {
                        "warning": f"EC2 instance {instance['InstanceId']} in region {region} has a public IP address",
                        "explanation": "Exposing EC2 instances to the internet with public IP addresses can increase security risks",
                        "recommendation": "Consider using a bastion host or a VPN connection to securely access EC2 instances without public IP addresses"}
                    warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs(" EC2 instances with public IP addresses", warnings)

    # Define the check_unassociated_eips function
    def check_unassociated_eips(region):
        warnings = []
        # Print the current check and region
        print(f"Checking unassociated EIPs in {region}...")
        # Check the current region in the EC2 client
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about all Elastic IP addresses (EIPs) in Elastic Compute Cloud (EC2) instances in the current region
        response = ec2.describe_addresses()
        # Check if the EIP is unassociated
        for eip in response['Addresses']:
            if 'AssociationId' not in eip:
                # Generate warning for all public EIPs in the EC2
                warning = {"warning": f"Unassociated EIP {eip['PublicIp']} in region {region}",
                            "explanation": "Having unassociated EIPs could cause issues with billing",
                            "recommendation": f"Should release the unassociated EIP {eip['PublicIp']} if not needed, using the EC2 console or the AWS CLI"}
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Unassociated EIPs", warnings)

    # Define the check_EC2_excessive_security_groups function
    def check_EC2_excessive_security_groups(region):
        warnings = []
        # Print the current check and region
        print(f"Checking security groups in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about all Elastic Compute Cloud (EC2) security groups in the current region
        response = ec2.describe_security_groups()
        # Check if the security group has excessive rules
        for security_groups in response['SecurityGroups']:
            if len(security_groups['IpPermissions']) > 15 or len(security_groups['IpPermissionsEgress']) > 15:
                # Generate warning for all the security group has excessive rules in the EC2
                warning = {
                    "warning": f"Security group {security_groups['GroupId']} in region {region} has excessive security group rules",
                    "explanation": "Excessive rules in the security groups can lead to increased security risks and struggles in management",
                    "recommendation": "Use AWS Network Firewall or merge the overlapping rules in the security group"}
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Excessive security group rules", warnings)

    # Define the check_network_acl_tags function
    def check_network_acl_tags(region):
        warnings = []
        # Print the current check and region
        print(f"Checking network ACLs tags in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about all Network ACLs in the current region
        response = ec2.describe_network_acls()
        # Check if the Network ACL has any tags
        for acl in response['NetworkAcls']:
            if not acl['Tags']:
                # Generate warning for all Network ACL that does not have any tags in the EC2
                warning = {
                    "warning": f"Network ACL {acl['NetworkAclId']} does not have any tags in region {region}",
                    "explanation": "Tagging resources makes it easier to organize resources, categorize, and search for them in AWS based on different criteria",
                    "recommendation": f"Use the EC2 console or the AWS CLI to add tags to Network ACL {acl['NetworkAclId']}"
                }
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Network ACL without tags", warnings)

    # Define the check_EC2_unused_EBS_volumes function
    def check_EC2_unused_EBS_volumes(region):
        warnings = []
        # Print the current check and region
        print(f"Checking unused EBS volumes in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every Elastic Block Store (EBS) volume in the current region
        response = ec2.describe_volumes()
        # Check if the volume is not in use
        for volume in response['Volumes']:
            # Create a dictionary with data about the unused volume
            if volume['State'] == 'available':
                volume_data = {"VolumeId": volume['VolumeId'], "State": volume['State'], "Region": region}
                # Generate warning for all unused volume in the EC2
                warning = {"warning": f"Unused EBS volume {volume['VolumeId']} in region {region}",
                            "explanation": "Having Unused EBS volumes could cause issues with billing and should regularly check them",
                            "recommendation": "remove any unused volumes to avoid unnecessary costs using the EC2 console or the AWS CLI"}
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("EC2 Unused EBS Volumes", warnings)


    # Define the check_ec2_key_based_login function
    def check_ec2_key_based_login(region):
        warnings = []
        # Print the current check and region
        print(f"Checking EC2 instances Key Based Login in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every Elastic Compute Cloud (EC2) instances in the current region
        response = ec2.describe_instances()
        # Check if the instance uses key-based login
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                for securityGroup in instance['SecurityGroups']:
                    groupId = securityGroup['GroupId']
                    groupResponse = ec2.describe_security_groups(GroupIds=[groupId])
                    for ipPermission in groupResponse['SecurityGroups'][0]['IpPermissions']:
                        if ipPermission.get('FromPort') == 22 and ipPermission.get('IpProtocol') == 'tcp':
                            for ipRange in ipPermission['IpRanges']:
                                if ipRange['CidrIp'] == '0.0.0.0/0':
                                    # Generate warning for all instance uses key-based login in the EC2
                                    warning = {
                                        "warning": f"EC2 instance {instance['InstanceId']} uses key-based login in region {region} ",
                                        "explanation": "Key-based login is an authentication method and it offers lower secure than other methods",
                                        "recommendation": "Use other secure authentication methods such as Identity and Access Management (IAM) roles or multi-factor authentication (MFA)"}
                                    warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("EC2 instances using key-based login", warnings)

    # Define the check_unused_vpgs function
    def check_unused_vpgs(region):
        warnings = []
        # Print the current check and region
        print(f"Checking unused VPCs in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every virtual private clouds (VPCs) in the current region
        response = ec2.describe_vpcs()
        # Check if any VPCs have an unused Virtual Private Gateway
        for vpc in response['Vpcs']:
            vpcId = vpc['VpcId']
            # Retrieve data about for VPN Gateways (responseVgws) in the current VPC
            responseVgws = ec2.describe_vpn_gateways(
                Filters=[
                    {'Name': 'attachment.vpc-id', 'Values': [vpcId]},
                    {'Name': 'state', 'Values': ['available']}
                ]
            )
            if not responseVgws['VpnGateways']:
                # Generate warning for all unused Virtual Private Gateway in the VPC
                warning = {"warning": f"VPC {vpcId} has unused Virtual Private Gateway in region {region}",
                            "explanation": "Unused Virtual Private Gateways cloud lead to security risks and result in avoidable expense.",
                            "recommendation": "Use the EC2 console or the AWS CLI to remove the unused Virtual Private Gateway from the VPC"}
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("unused Virtual Private Gateways", warnings)

    # Define the check_VPC_firewalls function
    def check_VPC_firewalls(region):
        warnings = []
        # Print the current check and region
        print(f"Checking VPC firewalls in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every virtual private clouds (VPCs) in the current region
        response = ec2.describe_vpcs()
        # Check the security group rules for each VPC
        for vpc in response['Vpcs']:
            vpcId = vpc['VpcId']
            security_groups = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpcId]}])[
                'SecurityGroups']
            for s_groups in security_groups:
                for permission in s_groups['IpPermissions']:
                    if permission.get('IpRanges') is not None and len(permission['IpRanges']) > 0:
                        for ipRange in permission['IpRanges']:
                            cidrIp = ipRange['CidrIp']
                            if cidrIp == '0.0.0.0/0':
                                # Generate warning for allow traffic from all IPs in the VPC
                                warning = {
                                    "warning": f"Security group {s_groups['GroupName']} allows traffic from all IPs in VPC {vpcId}",
                                    "explanation": "Allowing traffic from all IPs can leave resources vulnerable and exposed on the internet",
                                    "recommendation": "Use the EC2 console or the AWS CLI to restrict the inbound traffic to only the necessary IP addresses"}
                                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("VPC Firewalls", warnings)


    # Define the check_open_all_ports_egress function
    def check_open_all_ports_egress(region):
        warnings = []
        # Print the current check and region
        print(f"Checking security group egress rules in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every security group in the current EC2 client
        response = ec2.describe_security_groups()
        # Check if any security group has a rule that allows all ports and protocols for egress traffic
        for security_groups in response['SecurityGroups']:
            for rule in security_groups['IpPermissionsEgress']:
                if rule.get('IpProtocol') == '-1' and '0.0.0.0/0' in [cidr['CidrIp'] for cidr in rule.get('IpRanges', [])]:
                    warning = {
                        # Generate warning for all open ports egress
                        "warning": f"Security group {security_groups['GroupId']} allows all ports and protocols for egress traffic in region {region}",
                        "explanation": "Allowing all ports and protocols for egress traffic can leave resources vulnerable and lead to security risk",
                        "recommendation": "Use the EC2 console or the AWS CLI to restrict egress traffic to only necessary ports"}
                    warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Security groups with open all ports/protocols egress", warnings)


    # Define the check_unused_security_groups function
    def check_unused_security_groups(region):
        warnings = []
        # Print the current check and region
        print(f"Checking unused security groups in {region}...")
        # Check the current EC2 client in the region
        ec2 = boto3.client('ec2', region_name=region)
        # Retrieve data about every security group in the current EC2 client
        security_groups = ec2.describe_security_groups()['SecurityGroups']
        # Retrieve data about every running Elastic Compute Cloud (EC2) instances in the current region
        instances = ec2.describe_instances()
        # Create a set of all security group IDs associated with running instances
        instance_securityGroups = set()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for sec_groups in instance['SecurityGroups']:
                    instance_securityGroups.add(sec_groups['GroupId'])
        # Check if any security groups are unused
        for securityGroups in security_groups:
            if securityGroups['GroupId'] not in instance_securityGroups:
                # Generate warning for all unused security groups
                warning = {"warning": f"Security group {securityGroups['GroupId']} unused in region {region}",
                            "explanation": "Potential security risk may cause unauthorized access to Elastic Compute Cloud (EC2) instances for having unused security groups",
                            "recommendation": "Use the EC2 console or the AWS CLI to revoke unused security group"}
                warnings.append(warning)
        # Output the warnings
        EC2_VPC_outputs("Unused Security Groups", warnings)


    regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
    for region in regions:
        print(f"Checking in region: {region}...")
        check_EC2_EBS_volumes(region)
        check_open_ports(region)
        check_ec2_ebs_backup(region)
        check_security_groups_ingress(region)
        check_EC2_public_ips(region)
        check_unassociated_eips(region)
        check_EC2_excessive_security_groups(region)
        check_network_acl_tags(region)
        check_ec2_key_based_login(region)
        check_EC2_unused_EBS_volumes(region)
        check_unused_vpgs(region)
        check_VPC_firewalls(region)
        check_open_all_ports_egress(region)
        check_unused_security_groups(region)
        print("\n")


    print("End of The EC2 & VPC report\n")


    # Print all warnings to a log file
    write_EC2_to_file("txt", policy_warnings)


def EC2_VPC_outputs(policy_name, data):
        # assuming you have the policy name stored in a variable called "policy_name"
        if policy_name not in policy_warnings:
            policy_warnings[policy_name] = []
        for d in data:
            policy_warnings[policy_name].append(d)    


    
# Define the write_EC2_to_file function  
def write_EC2_to_file(file_format, policy_warnings):
        '''Write warnings and recommendations to a log file\n
        Parameters: file format\n
        Returns: filepath of written file'''

        filepath = 'logs/ec2_vpc_report.txt'
        if file_format == 'txt':
            with open(filepath, 'w') as file:
                for policy_name, warnings in policy_warnings.items():
                    file.write(
                        f"""----- Check Name: {policy_name} -----\n\n"""
                    )
                    for w in warnings:
                        file.write("| Warning | " + w['warning'] + "\n")
                        file.write("| Explanation | " + w['explanation'] + "\n")
                        file.write("| Recommendation | " + w['recommendation'] + "\n")
                        file.write("\n")
        return filepath
