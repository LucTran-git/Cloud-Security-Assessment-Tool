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

policy_docs = {}
policy_warnings = {} # dict of (list of dicts) 
            # { 'policy_name' : [{'warning' : 'text', 'explanation' : 'text', 'recommendation' : 'text'}, ...] }
            # We separate the warning info in this way to make it easier to format the report in different ways e.g. txt vs csv


###---------------------------------------------------EC2 & VPC SECTION----------------------------------------------------------------------

def check_EC2_VPC_configurations(ec2_clients):


    # Define the check_EC2_EBS_volumes function
    def check_EC2_EBS_volumes(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking EBS volumes in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all EBS volumes in the current region
            response = ec2.describe_volumes()
            # Check if the volume is unencrypted
            for volume in response['Volumes']:
                # Create a dictionary with information about the unencrypted volume
                if 'Encrypted' in volume and not volume['Encrypted']:
                    volume_info = {"VolumeId": volume['VolumeId'], "Encrypted": volume['Encrypted'], "Region": region}
                    warning = {"warning": f"Unencrypted EBS volume {volume['VolumeId']} in region {region}",
                               "explanation": "EBS volumes should be encrypted to protect data confidentiality",
                               "recommendation": "Encrypt the EBS volume using the EC2 console or the AWS CLI"}
                    warnings.append(warning)
        EC2_VPC_outputs("EC2 Unencrypted EBS volumes", warnings)

    # Define the check_ec2_ebs_backup function
    def check_ec2_ebs_backup(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking EBS backup in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all EC2 instances in the current region
            response = ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    # Check if instance has any EBS volumes
                    if 'BlockDeviceMappings' in instance:
                        for volume in instance['BlockDeviceMappings']:
                            volume_id = volume['Ebs']['VolumeId']
                            # Check if EBS volume has backup enabled
                            ebs = boto3.client('ec2', region_name=region)
                            ebs_response = ebs.describe_snapshots(
                                Filters=[{'Name': 'volume-id', 'Values': [volume_id]}])
                            if len(ebs_response['Snapshots']) == 0:
                                warning = {
                                    "warning": f"EBS volume {volume_id} for EC2 instance {instance_id} in region {region} has no backup enabled",
                                    "explanation": "EBS volumes backups are critical to ensure data durability and availability",
                                    "recommendation": "Enable EBS backups using the EC2 console or the AWS CLI"}
                                warnings.append(warning)
        EC2_VPC_outputs("EC2 EBS Backup", warnings)

    # Define the check_security_groups_ingress function
    def check_security_groups_ingress(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking security groups ingress in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all security groups in the current region
            response = ec2.describe_security_groups()
            # Check if any security group has a wide open ingress rule
            for security_group in response['SecurityGroups']:
                for permission in security_group['IpPermissions']:
                    if 'IpRanges' in permission and len(permission['IpRanges']) > 0 and \
                            permission['IpRanges'][0]['CidrIp'] == '0.0.0.0/0' and permission['FromPort'] == 0 and \
                            permission['IpProtocol'] == 'tcp':
                        warning = {
                            "warning": f"Wide open ingress rule found in security group {security_group['GroupId']} in region {region}",
                            "explanation": "Security groups should restrict access to only the necessary ports and IP ranges",
                            "recommendation": "Update the security group rules to restrict access to only the necessary ports and IP ranges"}
                        warnings.append(warning)
        EC2_VPC_outputs("Wide Open Ingress Rule in Security Groups", warnings)

    # Define the check_VPC_NAT_Gateways function
    def check_VPC_NAT_Gateways(ec2_clients):
        warnings = []
        # Get a list of all VPC regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]

        # Check for NAT Gateways in each region
        for region in regions:
            print(f"Checking NAT Gateways in {region}...")
            ec2_client = boto3.client('ec2', region_name=region)

            nat_gateways = ec2_client.describe_nat_gateways()['NatGateways']

            for nat_gateway in nat_gateways:
                if 'SubnetMappings' not in nat_gateway:
                    # NAT gateway has no subnet associations, skip it
                    continue

                public_subnet_ids = [nat_gateway_assoc['SubnetId'] for nat_gateway_assoc in
                                     nat_gateway['SubnetMappings'] if
                                     nat_gateway_assoc['NatGatewayId'] == nat_gateway['NatGatewayId'] and
                                     nat_gateway_assoc['SubnetPublicIp'] != None]
                private_subnet_ids = [nat_gateway_assoc['SubnetId'] for nat_gateway_assoc in
                                      nat_gateway['SubnetMappings'] if
                                      nat_gateway_assoc['NatGatewayId'] == nat_gateway['NatGatewayId'] and
                                      nat_gateway_assoc['SubnetPublicIp'] == None]

                if len(public_subnet_ids) > 0 and len(private_subnet_ids) == 0:
                    warning = {
                        "warning": f"Found NAT Gateway {nat_gateway['NatGatewayId']} in region {region} with a public subnet but no corresponding private subnet",
                        "explanation": "Having a public subnet without a corresponding private subnet can expose resources to the public internet",
                        "recommendation": f"Create a private subnet in the same Availability Zone as the public subnet and associate the NAT Gateway with it"
                    }

                    warnings.append(warning)

        EC2_VPC_outputs("VPC NAT Gateways", warnings)

    # Define the check_vpc_endpoint_exposure function
    def check_vpc_endpoint_exposure(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPC endpoint exposure in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all VPCs in the current region
            response = ec2.describe_vpcs()
            for vpc in response['Vpcs']:
                vpc_id = vpc['VpcId']
                # Check if VPC has any endpoints
                if 'EndpointServiceNames' in vpc:
                    for service_name in vpc['EndpointServiceNames']:
                        # Check if the endpoint service is exposed to the internet
                        endpoint_service = boto3.client('ec2', region_name=region)
                        endpoint_service_response = endpoint_service.describe_vpc_endpoint_services(
                            ServiceNames=[service_name])
                        if endpoint_service_response['ServiceDetails'][0]['ServiceType'] == 'Interface' and \
                                endpoint_service_response['ServiceDetails'][0]['AvailabilityZones']:
                            warning = {
                                "warning": f"VPC endpoint service {service_name} in VPC {vpc_id} in region {region} is exposed to the internet",
                                "explanation": "Exposing VPC endpoints to the internet can lead to security vulnerabilities",
                                "recommendation": "Configure the endpoint to not be exposed to the internet using the VPC console or the AWS CLI"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPC endpoint Exposure", warnings)

    # Define the check_unused_amis function
    def check_unused_amis(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]

        for region in regions:
            ec2 = boto3.resource('ec2', region_name=region)
            instances = ec2.instances.all()
            amis = ec2.images.filter(Owners=['self'])

            unused_amis = set([ami.id for ami in amis])

            for instance in instances:
                if instance.state['Name'] != 'terminated':
                    name = None
                    if instance.tags:
                        for tag in instance.tags:
                            if tag['Key'] == 'Name':
                                name = tag['Value']

                    for bdm in instance.block_device_mappings:
                        if 'Ebs' in bdm:
                            vol_id = bdm['Ebs']['VolumeId']
                            vol = ec2.Volume(vol_id)
                            attached_ami = vol.attachments[0]['InstanceId']

                            if attached_ami in unused_amis:
                                unused_amis.remove(attached_ami)

                    if name is None:
                        name = instance.id

            for ami in unused_amis:
                warning = {"warning": f"Unused Amazon Machine Image {ami} in region {region}",
                           "explanation": "Unused AMIs can take up storage space and increase costs",
                           "recommendation": "Deregister the unused AMI using the EC2 console or the AWS CLI"}
                warnings.append(warning)

        EC2_VPC_outputs("unused Amazon Machine Images (AMIs)", warnings)

    # Define the check_unused_vpc_igws function
    def check_unused_vpc_igws(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking unused VPC Internet Gateways in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all VPCs in the current region
            response = ec2.describe_vpcs()
            # Check if the VPC has an unused Internet Gateway
            for vpc in response['Vpcs']:
                vpc_id = vpc['VpcId']
                # Retrieve information about all Internet Gateways attached to the VPC
                igw_response = ec2.describe_internet_gateways(
                    Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
                # Check if any Internet Gateway is not attached to any instance
                for igw in igw_response['InternetGateways']:
                    if len(igw['Attachments']) == 0:
                        warning = {
                            "warning": f"Unused VPC Internet Gateway {igw['InternetGatewayId']} in VPC {vpc_id} and region {region}",
                            "explanation": "Unused Internet Gateways can be a security risk as they may allow unauthorized access to the VPC",
                            "recommendation": "Delete the unused Internet Gateway using the EC2 console or the AWS CLI"}
                        warnings.append(warning)
        EC2_VPC_outputs("unused VPC Internet Gateways", warnings)

    # Define the check_EC2_public_ips function
    def check_EC2_public_ips(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking EC2 instances Public IPs in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all EC2 instances in the current region
            response = ec2.describe_instances()
            # Check if the instance has a public IP address
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if 'PublicIpAddress' in instance:
                        warning = {
                            "warning": f"EC2 instance {instance['InstanceId']} in region {region} has a public IP address",
                            "explanation": "Exposing EC2 instances to the internet with public IP addresses can increase security risks",
                            "recommendation": "Consider using a bastion host or a VPN connection to securely access EC2 instances without public IP addresses"}
                        warnings.append(warning)
        EC2_VPC_outputs(" EC2 instances with public IP addresses", warnings)

    # Define the check_unused_vpgs function
    def check_unused_vpgs(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking unused VPCs in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all VPCs in the current region
            response = ec2.describe_vpcs()
            # Check if any VPCs have an unused Virtual Private Gateway
            for vpc in response['Vpcs']:
                vpc_id = vpc['VpcId']
                response_vgws = ec2.describe_vpn_gateways(
                    Filters=[
                        {'Name': 'attachment.vpc-id', 'Values': [vpc_id]},
                        {'Name': 'state', 'Values': ['available']}
                    ]
                )
                if not response_vgws['VpnGateways']:
                    warning = {"warning": f"Unused Virtual Private Gateway in VPC {vpc_id} in region {region}",
                               "explanation": "Unused Virtual Private Gateways may pose security risks and incur unnecessary charges",
                               "recommendation": "Remove the unused Virtual Private Gateway from the VPC using the AWS Management Console or the AWS CLI"}
                    warnings.append(warning)
        EC2_VPC_outputs("unused Virtual Private Gateways", warnings)

    # Define the check_ec2_elastic_ip_limits function
    def check_ec2_elastic_ip_limits(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking Elastic IP Limits in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            response = ec2.describe_account_attributes(AttributeNames=['max-elastic-ips'])
            max_elastic_ips = int(response['AccountAttributes'][0]['AttributeValues'][0]['AttributeValue'])
            elastic_ips = ec2.describe_addresses()
            num_elastic_ips = len(elastic_ips['Addresses'])
            if num_elastic_ips >= max_elastic_ips:
                warning = {"warning": f"Elastic IP limit reached in {region}",
                           "explanation": "Elastic IP addresses are limited per region and exceeding the limit can lead to additional charges",
                           "recommendation": "Release unused Elastic IP addresses or request an increase in the limit"}
                warnings.append(warning)
        EC2_VPC_outputs("EC2 Elastic IP Limits", warnings)

    # Define the check_unassociated_eips function
    def check_unassociated_eips(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking unassociated EIPs in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all EIPs in the current region
            response = ec2.describe_addresses()
            # Check if the EIP is unassociated
            for eip in response['Addresses']:
                if 'AssociationId' not in eip:
                    warning = {"warning": f"Unassociated EIP {eip['PublicIp']} in region {region}",
                               "explanation": "Unassociated EIPs can cause billing issues and should be released if not needed",
                               "recommendation": f"Release the unassociated EIP {eip['PublicIp']} using the EC2 console or the AWS CLI"}
                    warnings.append(warning)
        EC2_VPC_outputs("Unassociated EIPs", warnings)

    # Define the check_EC2_excessive_security_groups function
    def check_EC2_excessive_security_groups(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking security groups in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all security groups in the current region
            response = ec2.describe_security_groups()
            # Check if the security group has excessive rules
            for sg in response['SecurityGroups']:
                if len(sg['IpPermissions']) > 15 or len(sg['IpPermissionsEgress']) > 15:
                    warning = {
                        "warning": f"Excessive security group rules found in security group {sg['GroupId']} in region {region}",
                        "explanation": "Security groups with excessive rules can lead to increased security risks and difficulties in management",
                        "recommendation": "Simplify the security group rules by consolidating overlapping rules, or consider using AWS Network Firewall"}
                    warnings.append(warning)
        EC2_VPC_outputs("Excessive security group rules", warnings)

    # Define the check_network_acl_tags function
    def check_network_acl_tags(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking network ACLs tags in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all Network ACLs in the current region
            response = ec2.describe_network_acls()
            # Check if the Network ACL has any tags
            for acl in response['NetworkAcls']:
                if not acl['Tags']:
                    warning = {
                        "warning": f"Network ACL {acl['NetworkAclId']} in region {region} does not have any tags",
                        "explanation": "Tagging resources makes it easier to identify, organize, and search for them later",
                        "recommendation": f"Add tags to Network ACL {acl['NetworkAclId']} using the EC2 console or the AWS CLI"
                    }
                    warnings.append(warning)
        EC2_VPC_outputs("Network ACL without tags", warnings)

    # Define the check_open_all_ports_egress function
    def check_open_all_ports_egress(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking security group egress rules in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all security groups in the current region
            response = ec2.describe_security_groups()
            # Check if any security group has a rule that allows all ports and protocols for egress traffic
            for sg in response['SecurityGroups']:
                for rule in sg['IpPermissionsEgress']:
                    if rule.get('IpProtocol') == '-1' and '0.0.0.0/0' in [cidr['CidrIp'] for cidr in
                                                                          rule.get('IpRanges', [])]:
                        warning = {
                            "warning": f"Security group {sg['GroupId']} in region {region} allows all ports and protocols for egress traffic",
                            "explanation": "Allowing all ports and protocols for egress traffic can pose a security risk as it allows any outbound traffic",
                            "recommendation": "Restrict egress traffic to only necessary ports and protocols using the EC2 console or the AWS CLI"}
                        warnings.append(warning)
        EC2_VPC_outputs("Security groups with open all ports/protocols egress", warnings)

    # Define the check_open_dns function
    def check_open_dns(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking DNS settings in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all VPCs in the current region
            response = ec2.describe_vpcs()
            for vpc in response['Vpcs']:
                # Check if DNS resolution is enabled
                if not vpc.get('DnsSupport', False):
                    warning = {"warning": f"DNS resolution is not enabled for VPC {vpc['VpcId']} in region {region}",
                               "explanation": "Enabling DNS resolution can help resolve domain names to IP addresses for instances in your VPC",
                               "recommendation": "Enable DNS resolution for your VPC using the VPC console or the AWS CLI"}
                    warnings.append(warning)
                # Check if DNS hostnames are enabled
                if not vpc.get('DnsHostnames', False):
                    warning = {"warning": f"DNS hostnames are not enabled for VPC {vpc['VpcId']} in region {region}",
                               "explanation": "Enabling DNS hostnames can help resolve instance hostnames to domain names in your VPC",
                               "recommendation": "Enable DNS hostnames for your VPC using the VPC console or the AWS CLI"}
                    warnings.append(warning)
        EC2_VPC_outputs("Open DNS in VPCs", warnings)

    # Define the check_open_CIFS function
    def check_open_CIFS(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking open CIFS in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all instances in the current region
            response = ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    # Check for open CIFS port (445)
                    for sg in instance['SecurityGroups']:
                        group_id = sg['GroupId']
                        group = ec2.describe_security_groups(GroupIds=[group_id])['SecurityGroups'][0]
                        for ip_permission in group['IpPermissions']:
                            if ip_permission['IpProtocol'] == 'tcp' and \
                                    ip_permission['FromPort'] <= 445 <= ip_permission['ToPort'] and \
                                    {'CidrIp': '0.0.0.0/0'} in ip_permission['IpRanges']:
                                warning = {
                                    "warning": f"Open CIFS port (445) found in security group {group_id} of instance {instance['InstanceId']} in region {region}",
                                    "explanation": "Open CIFS ports can allow unauthorized access to files on the instance",
                                    "recommendation": "Close the CIFS port (445) in the security group using the EC2 console or the AWS CLI"}
                                warnings.append(warning)
        EC2_VPC_outputs("Open CIFS ports", warnings)

    # Define the check_ec2_key_based_login function
    def check_ec2_key_based_login(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking EC2 instances Key Based Login in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all EC2 instances in the current region
            response = ec2.describe_instances()
            # Check if the instance uses key-based login
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for security_group in instance['SecurityGroups']:
                        group_id = security_group['GroupId']
                        group_response = ec2.describe_security_groups(GroupIds=[group_id])
                        for ip_permission in group_response['SecurityGroups'][0]['IpPermissions']:
                            if ip_permission.get('FromPort') == 22 and ip_permission.get('IpProtocol') == 'tcp':
                                for ip_range in ip_permission['IpRanges']:
                                    if ip_range['CidrIp'] == '0.0.0.0/0':
                                        warning = {
                                            "warning": f"EC2 instance {instance['InstanceId']} in region {region} uses key-based login",
                                            "explanation": "Key-based login can be less secure than other authentication methods",
                                            "recommendation": "Use a more secure authentication method, such as multi-factor authentication or IAM roles"}
                                        warnings.append(warning)
        EC2_VPC_outputs("EC2 instances using key-based login", warnings)

    # Define the check_EC2_FTP function
    def check_EC2_FTP(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking FTP in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all instances in the current region
            response = ec2.describe_instances()
            # Check if any instance has an open FTP port
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for security_group in instance['SecurityGroups']:
                        if 'IpPermissions' in security_group:
                            for ip_permission in security_group['IpPermissions']:
                                if ip_permission.get('FromPort') == 21 and ip_permission.get('IpProtocol') == 'tcp':
                                    warning = {
                                        "warning": f"EC2 instance {instance['InstanceId']} in region {region} has an open FTP port",
                                        "explanation": "FTP is an insecure protocol and should not be used to transfer sensitive data",
                                        "recommendation": "Disable FTP and use a more secure protocol like SFTP or SCP to transfer data"}
                                    warnings.append(warning)
            EC2_VPC_outputs("EC2 FTP Open Ports", warnings)

    # Define the check_VPC_firewalls function
    def check_VPC_firewalls(ec2_clients):
        warnings = []
        # Get a list of all VPC regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPC firewalls in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all VPCs in the current region
            response = ec2.describe_vpcs()
            # Check the security group rules for each VPC
            for vpc in response['Vpcs']:
                vpc_id = vpc['VpcId']
                security_groups = ec2.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])[
                    'SecurityGroups']
                for sg in security_groups:
                    for permission in sg['IpPermissions']:
                        if permission.get('IpRanges') is not None and len(permission['IpRanges']) > 0:
                            for ip_range in permission['IpRanges']:
                                cidr_ip = ip_range['CidrIp']
                                if cidr_ip == '0.0.0.0/0':
                                    warning = {
                                        "warning": f"Security group {sg['GroupName']} in VPC {vpc_id} allows traffic from all IPs",
                                        "explanation": "Allowing traffic from all IPs can make the resources exposed to the internet",
                                        "recommendation": "Restrict the inbound traffic to only the necessary IP addresses or ranges"}
                                    warnings.append(warning)
        EC2_VPC_outputs("VPC Firewalls", warnings)

    # Call the functions and populate the policy_warnings dictionary
    check_EC2_EBS_volumes(ec2_clients)
    check_ec2_ebs_backup(ec2_clients)
    check_security_groups_ingress(ec2_clients)
    check_EC2_public_ips(ec2_clients)
    check_unused_vpgs(ec2_clients)
    check_unassociated_eips(ec2_clients)
    check_EC2_excessive_security_groups(ec2_clients)
    check_network_acl_tags(ec2_clients)
    check_open_all_ports_egress(ec2_clients)
    check_open_dns(ec2_clients)
    check_ec2_key_based_login(ec2_clients)
    check_VPC_firewalls(ec2_clients)
    #check_VPC_NAT_Gateways(ec2_clients)
    #check_vpc_endpoint_exposure(ec2_clients)
    #check_unused_amis(ec2_clients)
    #check_unused_vpc_igws(ec2_clients)
    #check_ec2_elastic_ip_limits(ec2_clients)
    #check_open_CIFS(ec2_clients)
    #check_EC2_FTP(ec2_clients)





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
