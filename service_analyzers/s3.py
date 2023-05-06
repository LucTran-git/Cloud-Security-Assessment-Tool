import boto3
import json
import botocore
from botocore.exceptions import ClientError






def check_s3_bucket_acl(session, s3_client, buckets):
    warnings = []
    
    for bucket in buckets:
        print(f"Checking S3 bucket ACLs in {bucket['Name']}...")
        region = s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
        s3 = session.client('s3', region_name=region)
        bucket_name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            grants = acl['Grants']
            for grant in grants:
                grantee = grant['Grantee']
                
                if 'URI' in grantee and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    warning = {"warning": f"S3 bucket {bucket_name} in region {region} has public read access",
                               "explanation": "Public read access can allow anyone to view the contents of a bucket",
                               "recommendation": f"Update the bucket ACL for {bucket_name} to restrict public access using the S3 console or the AWS CLI"}
                    warnings.append(warning)
                    
        except s3.exceptions.ClientError as e:
            print(f"Error checking S3 bucket {bucket_name} in region {region}: {e}")
    
    return warnings





def check_s3_bucket_policy(s3_client, buckets):
    warnings = []
    for bucket in buckets:
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket['Name'])
            if policy['Policy'] != '':
                policy_statement = json.loads(policy['Policy'])['Statement']
               
                if isinstance(policy_statement, list):
                    for statement in policy_statement:
                        if 'Effect' in statement  and 'Principal' in statement:
                            principal = statement['Principal']
                            if '*' in principal or 'AWS' in principal and principal['AWS'] == '*':
                                warning = {"warning": f"S3 bucket {bucket['Name']} has a public bucket policy",
                                           "explanation": "Public bucket policies can potentially allow unauthorized access to data",
                                           "recommendation": f"Review the bucket policy for {bucket['Name']} and adjust permissions if necessary using the S3 console or the AWS CLI"}
                                warnings.append(warning)
                                break
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code != 'NoSuchBucketPolicy':
                print(f"Error checking S3 bucket {bucket['Name']}: {e}")
    return warnings






def check_s3_service_encryption(s3_client):
    """
    Check if the S3 service has encryption enabled for all regions.
    """
    warnings = []

    bucket_list = s3_client.list_buckets()

    for bucket in bucket_list['Buckets']:
        print(f"Checking S3 encryption for {bucket['Name']} region...")
        s3 = boto3.client('s3', region_name=s3_client.meta.region_name)
        try:
            
            encryption = s3_client.get_bucket_encryption(Bucket=bucket['Name'])['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            if encryption != 'AES256':
                warning = {"warning": f"S3 service in {bucket['Name']} region is not encrypted with AES256 algorithm",
                           "explanation": "S3 service should be encrypted to protect data confidentiality",
                           "recommendation": f"Enable default encryption for all S3 buckets in {bucket['Name']} region using the S3 console or the AWS CLI"}
                warnings.append(warning)
            else:
                warning = {"warning": f"S3 service in {bucket['Name']} region is encrypted with AES256 algorithm",
                           "explanation": "S3 service should be encrypted to protect data confidentiality",
                           "recommendation": f"Enable default encryption for all S3 buckets in {bucket['Name']} region using the S3 console or the AWS CLI"}
                warnings.append(warning)
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Access denied when checking S3 encryption for {bucket['Name']} region: {e}")
            elif e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                warning = {"warning": f"S3 service in {bucket['Name']} region does not have default encryption enabled",
                           "explanation": "S3 service should be encrypted to protect data confidentiality",
                           "recommendation": f"Enable default encryption for all S3 buckets in {bucket['Name']} region using the S3 console or the AWS CLI"}
                warnings.append(warning)
            else:
                print(f"Error checking S3 encryption for {bucket['Name']} region: {e}")

    return warnings







def check_s3_object_ownership(s3_client, expected_owner_id):
    """
    Check if the S3 objects are owned by the expected owner.
    """
    warnings = []

    bucket_list = s3_client.list_buckets()

    for bucket in bucket_list['Buckets']:
        print(f"Checking S3 objects ownership for {bucket['Name']} bucket...")
        s3 = boto3.client('s3', region_name=s3_client.meta.region_name)
        try:
            response = s3_client.list_objects_v2(Bucket=bucket['Name'])
            if 'Contents' in response:
                for obj in response['Contents']:
                    owner_id = obj['Owner']['ID']
                    print(owner_id)
                    if owner_id != expected_owner_id:
                        warning = {"warning": f"Object {obj['Key']} in {bucket['Name']} bucket is not owned by the expected owner",
                                   "explanation": "Object ownership is important for security and access control",
                                   "recommendation": f"Update the object ownership or access control settings for the {obj['Key']} object in {bucket['Name']} bucket"}
                        warnings.append(warning)
        except ClientError as e:
            print(f"Error checking S3 objects ownership for {bucket['Name']} bucket: {e}")

    return warnings








def check_s3_bucket_encryption_in_transit(s3_client, buckets):
    warnings = []
    
    for b in buckets:
        print(f"Checking S3 bucket encryption in transit in {b['Name']}...")
        s3 = boto3.client('s3', region_name=b['Name'])
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                response = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                status = response['PolicyStatus']['IsPublic']
                if status:
                    warning = {"warning": f"S3 bucket {bucket_name} in region {b['Name']} has a public bucket policy",
                               "explanation": "Public bucket policies can potentially allow unauthorized access to data",
                               "recommendation": f"Review the bucket policy for {bucket_name} and adjust permissions if necessary using the S3 console or the AWS CLI"}
                    warnings.append(warning)
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    continue
                else:
                    print(f"Error checking S3 bucket {bucket_name} in region {b['Name']}: {e}")
    return warnings





import json
import os



def get_all_warnings(session, s3_client, buckets):
    get_all_warnings = []
    print('Starting create your warning file................................')
    result_s3_bucket_acl = check_s3_bucket_acl(session, s3_client, buckets)
    result_s3_bucket_policy = check_s3_bucket_policy(s3_client, buckets)
    result_s3_service_encryption = check_s3_service_encryption(s3_client)
    result_s3_object_ownership = check_s3_object_ownership(s3_client, 9641163299277)
    result_s3_bucket_encryption_in_transit = check_s3_bucket_encryption_in_transit(s3_client)

    get_all_warnings.append(result_s3_bucket_acl)
    get_all_warnings.append(result_s3_bucket_policy)
    get_all_warnings.append(result_s3_service_encryption)
    get_all_warnings.append(result_s3_object_ownership)
    get_all_warnings.append(result_s3_bucket_encryption_in_transit)

    return get_all_warnings




def write_warnings_to_file(warnings):
    folder_path = './logs/'
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    filename =  folder_path + 'warnings.txt'
    with open(filename, 'w') as f:
        json.dump(warnings, f)
        print('successfuly created json file!')


def S3_starting_function(session):
    # Create S3 client

    s3_client = session.client('s3')

    # Get all S3 bucket names
    response = s3_client.list_buckets()
    buckets = response['Buckets']

    write_warnings_to_file(get_all_warnings(session, s3_client, buckets))


