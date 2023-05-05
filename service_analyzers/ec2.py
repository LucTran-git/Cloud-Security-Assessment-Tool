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

    # Define the check_vpc_open_mysql function
    def check_vpc_open_mysql(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open MySQL in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve information about all VPCs in the current region
            for vpc in ec2.vpcs.all():
                for sg in vpc.security_groups.all():
                    # Check if the security group allows inbound traffic on port 3306 (MySQL)
                    for ip_permission in sg.ip_permissions:
                        if ip_permission['IpProtocol'] == 'tcp' and ip_permission['FromPort'] == 3306 and \
                                any([ip_range['CidrIp'] == '0.0.0.0/0' for ip_range in ip_permission['IpRanges']]):
                            warning = {
                                "warning": f"Security Group {sg.id} in VPC {vpc.id} in region {region} allows open MySQL port to the internet",
                                "explanation": "Allowing inbound traffic on port 3306 to the internet can expose your MySQL server to security risks",
                                "recommendation": "Restrict the security group to only allow MySQL traffic from trusted sources"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPC Open MySQL Ports", warnings)

    # Define the check_vpc_open_oracle function
    def check_vpc_open_oracle(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open Oracle in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an Oracle security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 1521 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0].get('CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Oracle port (1521) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Oracle should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Oracle to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Oracle", warnings)

    # Define the check_vpc_open_netbios function
    def check_vpc_open_netbios(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open Netbios in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a NetBIOS security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 137 and ip_permission.get('IpProtocol') == 'udp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open NetBIOS port (137/138) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "NetBIOS should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to NetBIOS to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for NetBIOS", warnings)

    # Define the check_vpc_open_postgres function
    def check_vpc_open_postgres(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open Postgres in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a PostgreSQL security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 5432 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open PostgreSQL port (5432) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "PostgreSQL should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to PostgreSQL to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for PostgreSQL", warnings)

    # Define the check_vpc_open_kibana function
    def check_vpc_open_kibana(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open Kibana in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a Kibana security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 5601 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Kibana port (5601) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Kibana should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Kibana to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Kibana", warnings)

    # Define the check_vpc_open_adw function
    def check_vpc_open_adw(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open ADW in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an Oracle ADW security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 1522 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Oracle ADW port (1522) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Oracle ADW should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Oracle ADW to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Oracle Auto Data Warehouse", warnings)

    # Define the check_vpc_open_hdfs function
    def check_vpc_open_hdfs(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open HGFS in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a Hadoop HDFS NameNode WebUI security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 50070 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Hadoop HDFS NameNode WebUI port (50070) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Hadoop HDFS NameNode WebUI should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Hadoop HDFS NameNode WebUI to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Hadoop HDFS NameNode WebUI", warnings)

    # Define the check_vpc_open_ftp function
    def check_vpc_open_ftp(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open FTP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an FTP security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 21 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open FTP port (21) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "FTP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to FTP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for FTP", warnings)

    # Define the check_vpc_open_docker function
    def check_vpc_open_docker(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open Docker in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a Docker security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 2375 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Docker port (2375) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Docker should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Docker to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Docker", warnings)

    # Define the check_vpc_open_cifs function
    def check_vpc_open_cifs(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open CIFS in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a CIFS security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 445 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open CIFS port (445) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "CIFS should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to CIFS to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for CIFS", warnings)

    # Define the check_vpc_open_rdp function
    def check_vpc_open_rdp(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open RDP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an RDP security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 3389 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open RDP port (3389) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "RDP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to RDP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for RDP", warnings)

    # Define the check_vpc_open_rpc function
    def check_vpc_open_rpc(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open RPC in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an RPC security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 135 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open RPC port (135) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "RPC should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to RPC to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for RPC", warnings)

    # Define the check_vpc_open_salt function
    def check_vpc_open_salt(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open Salt in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a Salt security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 4505 and ip_permission.get('ToPort') == 4506 and
                                ip_permission.get('IpProtocol') == 'tcp' and ip_permission.get('IpRanges')[0][
                                    'CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Salt port (4505/4506) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Salt should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Salt to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Salt", warnings)

    # Define the check_vpc_open_smb function
    def check_vpc_open_smb(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open SMB over TCP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an SMB over TCP security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 445 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges')[0]['CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open SMB over TCP port (445) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "SMB over TCP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to SMB over TCP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for SMB over TCP", warnings)

    # Define the check_vpc_open_smtp function
    def check_vpc_open_smtp(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open SMTP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has an SMTP security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 25 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0][
                                    'CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open SMTP port (25) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "SMTP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to SMTP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for SMTP", warnings)

    # Define the check_vpc_open_sql_server function
    def check_vpc_open_sql_server(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for SQL Server in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a SQL Server security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 1433 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0][
                                    'CidrIp'] == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open SQL Server port (1433) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "SQL Server should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to SQL Server to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for SQL Server", warnings)

    # Define the check_vpc_open_ssh function
    def check_vpc_open_ssh(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for SSH in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 22 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open SSH port (22) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "SSH should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to SSH to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for SSH", warnings)

    # Define the check_vpc_open_telnet function
    def check_vpc_open_telnet(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Telnet in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            # Retrieve all VPCs in the current region
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                # Check if the VPC has a Telnet security group rule open to the internet
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 23 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Telnet port (23) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Telnet should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Telnet to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Telnet", warnings)

    # Define the check_vpc_open_vnc function
    def check_vpc_open_vnc(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for VNC Client in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 5900 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open VNC Client port (5900) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "VNC client should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to VNC client to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for VNC Client", warnings)

    # Define the check_vpc_open_vnc_server function
    def check_vpc_open_vnc_server(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for VNC Server in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 5900 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open VNC Server port (5900) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "VNC server should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to VNC server to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for VNC Server", warnings)

    # Define the check_vpc_open_mongodb function
    def check_vpc_open_mongodb(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for MongoDB in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 27017 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open MongoDB port (27017) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "MongoDB should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to MongoDB to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for MongoDB", warnings)

    # Define the check_vpc_open_cassandra function
    def check_vpc_open_cassandra(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Cassandra Client in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 9042 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Cassandra Client port (9042) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Cassandra Client should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Cassandra Client to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Cassandra Client", warnings)

    # Define the check_vpc_open_cassandra_internode function
    def check_vpc_open_cassandra_internode(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Cassandra Internode in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 7000 and ip_permission.get('ToPort') == 7001 and
                                ip_permission.get('IpProtocol') == 'tcp' and ip_permission.get('IpRanges') and
                                ip_permission.get('IpRanges')[0].get('CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Cassandra internode ports (7000-7001) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Cassandra internode should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Cassandra internode to a trusted set of IP addresses or use a VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Cassandra Internode", warnings)

    # Define the check_vpc_open_cassandra_monitoring function
    def check_vpc_open_cassandra_monitoring(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Cassandra Monitoring in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 7199 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Cassandra Monitoring port (7199) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Cassandra Monitoring should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Cassandra Monitoring to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Cassandra Monitoring", warnings)

    # Define the check_vpc_open_cassandra_thrift function
    def check_vpc_open_cassandra_thrift(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Cassandra Thrift in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 9160 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Cassandra Thrift port (9160) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Cassandra Thrift should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Cassandra Thrift to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Cassandra Thrift", warnings)

    # Define the check_vpc_open_ldap function
    def check_vpc_open_ldap(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for LDAP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 389 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open LDAP port (389) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "LDAP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to LDAP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for LDAP", warnings)

    # Define the check_vpc_open_ldaps function
    def check_vpc_open_ldaps(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for LDAPS in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 636 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open LDAPS port (636) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "LDAPS should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to LDAPS to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for LDAPS", warnings)

    # Define the check_vpc_open_snmp function
    def check_vpc_open_snmp(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for SNMP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 161 and ip_permission.get('IpProtocol') == 'udp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open SNMP port (161) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "SNMP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to SNMP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for SNMP", warnings)

    # Define the check_vpc_open_memcached function
    def check_vpc_open_memcached(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Memcached in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 11211 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Memcached port (11211) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Memcached should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Memcached to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Memcached", warnings)

    # Define the check_vpc_open_redis function
    def check_vpc_open_redis(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for Redis in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 6379 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open Redis port (6379) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "Redis should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to Redis to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for Redis", warnings)

    # Define the check_vpc_open_http function
    def check_vpc_open_http(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for HTTP in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 80 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open HTTP port (80) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "HTTP should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to HTTP to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for HTTP", warnings)

    # Define the check_vpc_open_https function
    def check_vpc_open_https(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking VPCs Open for HTTPS in {region}...")
            ec2 = boto3.resource('ec2', region_name=region)
            vpcs = list(ec2.vpcs.all())
            for vpc in vpcs:
                for sg in vpc.security_groups.all():
                    for ip_permission in sg.ip_permissions:
                        if (ip_permission.get('FromPort') == 443 and ip_permission.get('IpProtocol') == 'tcp' and
                                ip_permission.get('IpRanges') and ip_permission.get('IpRanges')[0].get(
                                    'CidrIp') == '0.0.0.0/0'):
                            warning = {
                                "warning": f"Open HTTPS port (443) found in security group {sg.group_id} of VPC {vpc.id} in region {region}",
                                "explanation": "HTTPS should not be open to the internet as it is a security risk",
                                "recommendation": "Restrict access to HTTPS to a trusted set of IP addresses or VPN"}
                            warnings.append(warning)
        EC2_VPC_outputs("VPCs Open for HTTPS", warnings)

    # Define the check_unused_security_groups function
    def check_unused_security_groups(ec2_clients):
        warnings = []
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking unused security groups in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Get a list of all security groups in the current region
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            # Retrieve information about all running instances in the current region
            instances = ec2.describe_instances()
            # Create a set of all security group IDs associated with running instances
            instance_sgs = set()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    for sg in instance['SecurityGroups']:
                        instance_sgs.add(sg['GroupId'])
            # Check if any security groups are unused
            for sg in security_groups:
                if sg['GroupId'] not in instance_sgs:
                    warning = {"warning": f"Unused security group {sg['GroupId']} in region {region}",
                               "explanation": "Unused security groups are a potential security risk as they may allow unauthorized access to instances",
                               "recommendation": "Delete the unused security group using the EC2 console or the AWS CLI"}
                    warnings.append(warning)
        EC2_VPC_outputs("Unused Security Groups", warnings)

    # Define the check_EC2_unused_EBS_volumes function
    def check_EC2_unused_EBS_volumes(ec2_clients):
        warnings = []
        # Get a list of all available regions
        regions = [region['RegionName'] for region in ec2_clients.describe_regions()['Regions']]
        for region in regions:
            print(f"Checking unused EBS volumes in {region}...")
            ec2 = boto3.client('ec2', region_name=region)
            # Retrieve information about all EBS volumes in the current region
            response = ec2.describe_volumes()
            # Check if the volume is not in use
            for volume in response['Volumes']:
                # Create a dictionary with information about the unused volume
                if volume['State'] == 'available':
                    volume_info = {"VolumeId": volume['VolumeId'], "State": volume['State'], "Region": region}
                    warning = {"warning": f"Unused EBS volume {volume['VolumeId']} in region {region}",
                               "explanation": "Unused EBS volumes are billed, so it's important to regularly check for and remove any unused volumes to avoid unnecessary costs",
                               "recommendation": "Check if the volume is still needed and if not, delete it using the EC2 console or the AWS CLI"}
                    warnings.append(warning)
        EC2_VPC_outputs("EC2 Unused EBS Volumes", warnings)


    check_EC2_EBS_volumes(ec2_clients)
    check_ec2_ebs_backup(ec2_clients)
    check_security_groups_ingress(ec2_clients)
    check_EC2_public_ips(ec2_clients)
    check_unassociated_eips(ec2_clients)
    check_EC2_excessive_security_groups(ec2_clients)
    check_ec2_key_based_login(ec2_clients)
    check_EC2_unused_EBS_volumes(ec2_clients)
    check_unused_vpgs(ec2_clients)
    check_VPC_firewalls(ec2_clients)
    check_network_acl_tags(ec2_clients)
    check_open_all_ports_egress(ec2_clients)
    check_open_dns(ec2_clients)
    check_vpc_open_oracle(ec2_clients)
    check_vpc_open_mysql(ec2_clients)
    check_vpc_open_netbios(ec2_clients)
    check_vpc_open_postgres(ec2_clients)
    check_vpc_open_kibana(ec2_clients)
    check_vpc_open_adw(ec2_clients)
    check_vpc_open_hdfs(ec2_clients)
    check_vpc_open_ftp(ec2_clients)
    check_vpc_open_docker(ec2_clients)
    check_vpc_open_cifs(ec2_clients)
    check_vpc_open_rdp(ec2_clients)
    check_vpc_open_rpc(ec2_clients)
    check_vpc_open_salt(ec2_clients)
    check_vpc_open_smb(ec2_clients)
    check_vpc_open_smtp(ec2_clients)
    check_vpc_open_sql_server(ec2_clients)
    check_vpc_open_ssh(ec2_clients)
    check_vpc_open_telnet(ec2_clients)
    check_vpc_open_vnc(ec2_clients)
    check_vpc_open_vnc_server(ec2_clients)
    check_vpc_open_mongodb(ec2_clients)
    check_vpc_open_cassandra(ec2_clients)
    check_vpc_open_cassandra_internode(ec2_clients)
    check_vpc_open_cassandra_monitoring(ec2_clients)
    check_vpc_open_cassandra_thrift(ec2_clients)
    check_vpc_open_ldap(ec2_clients)
    check_vpc_open_ldaps(ec2_clients)
    check_vpc_open_snmp(ec2_clients)
    check_vpc_open_memcached(ec2_clients)
    check_vpc_open_redis(ec2_clients)
    check_vpc_open_http(ec2_clients)
    check_vpc_open_https(ec2_clients)
    check_unused_security_groups(ec2_clients)


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
