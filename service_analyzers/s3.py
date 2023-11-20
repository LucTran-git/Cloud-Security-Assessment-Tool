import boto3
import json
import os
import logging
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor
from os import cpu_count


class S3SecurityChecker:
    def __init__(self, session):
        # Initialize session using environment variables
        # self.session = boto3.Session(
        #     aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        #     aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY")
        # )
        self.session = session
        self.s3_client = self.session.client('s3')
        self.buckets = self._get_all_buckets()

    def _get_all_buckets(self):
        response = self.s3_client.list_buckets()
        return response['Buckets']

    def _get_region_for_bucket(self, bucket_name):
        return self.s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']

    def check_s3_bucket_acl(self, bucket):
        """
        Check if the S3 buckets have appropriate Access Control Lists (ACLs) to prevent public access.
        """
        warnings = []
        bucket_name = bucket['Name']
        region = self._get_region_for_bucket(bucket_name)
        s3 = self.session.client('s3', region_name=region)
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant['Grantee']
                if 'URI' in grantee and grantee['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    warning = {
                        "warning": f"S3 bucket {bucket_name} in region {region} has public read access",
                        "explanation": "Public read access can allow anyone to view the contents of a bucket",
                        "recommendation": f"Update the bucket ACL for {bucket_name} to restrict public access"
                    }
                    warnings.append(warning)
        except ClientError as e:
            logging.error(f"Error checking S3 bucket {bucket_name} in region {region}: {e}")
        return warnings


    def check_s3_bucket_policy(self, bucket):
        """
        Review the S3 bucket policies to ensure they don't grant public or overly permissive access.
        """
        warnings = []
        bucket_name = bucket['Name']
        region = self._get_region_for_bucket(bucket_name)
        s3 = self.session.client('s3', region_name=region)
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_statement = json.loads(policy['Policy'])['Statement']
            for statement in policy_statement:
                if 'Effect' in statement and 'Principal' in statement:
                    principal = statement['Principal']
                    if '*' in principal or ('AWS' in principal and principal['AWS'] == '*'):
                        warning = {
                            "warning": f"S3 bucket {bucket_name} in region {region} has a public bucket policy",
                            "explanation": "Public bucket policies can potentially allow unauthorized access to data",
                            "recommendation": f"Review the bucket policy for {bucket_name} and adjust permissions if necessary"
                        }
                        warnings.append(warning)
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                logging.error(f"Error checking S3 bucket {bucket_name} in region {region}: {e}")
        return warnings


    def check_s3_service_encryption(self, bucket):
        """
        Check if the S3 service has encryption enabled for the specified bucket.
        """
        warnings = []
        bucket_name = bucket['Name']
        region = self._get_region_for_bucket(bucket_name)
        s3 = self.session.client('s3', region_name=region)
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            sse_algorithm = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            if sse_algorithm != 'AES256':
                warning = {
                    "warning": f"S3 bucket {bucket_name} in region {region} is not encrypted with AES256 algorithm",
                    "explanation": "S3 service should be encrypted to protect data confidentiality",
                    "recommendation": f"Enable default encryption for {bucket_name} using AES256 algorithm"
                }
                warnings.append(warning)
            else:
                warning = {
                    "warning": f"S3 bucket {bucket_name} in region {region} is encrypted with AES256 algorithm",
                    "explanation": "S3 service is encrypted to protect data confidentiality",
                    "recommendation": f"Ensure all S3 buckets in the account are similarly encrypted"
                }
                warnings.append(warning)
        except ClientError as e:
            if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                logging.error(f"Error checking S3 encryption for {bucket_name} in region {region}: {e}")
            else:
                warning = {
                    "warning": f"S3 bucket {bucket_name} in region {region} does not have default encryption enabled",
                    "explanation": "S3 service should be encrypted to protect data confidentiality",
                    "recommendation": f"Enable default encryption for {bucket_name}"
                }
                warnings.append(warning)
        return warnings


    def check_s3_object_ownership(self, bucket, expected_owner_id):
        """
        Validate the ownership of S3 objects in the specified bucket to ensure they are owned by the expected AWS account or entity.
        """
        warnings = []
        bucket_name = bucket['Name']
        region = self._get_region_for_bucket(bucket_name)
        s3 = self.session.client('s3', region_name=region)
        try:
            response = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                for obj in response['Contents']:
                    owner_id = obj['Owner']['ID']
                    if owner_id != expected_owner_id:
                        warning = {
                            "warning": f"Object {obj['Key']} in {bucket_name} is not owned by the expected owner",
                            "explanation": "Object ownership is important for security and access control",
                            "recommendation": f"Update the object ownership or access control settings for the {obj['Key']} in {bucket_name}"
                        }
                        warnings.append(warning)
        except ClientError as e:
            logging.error(f"Error checking S3 objects ownership for {bucket_name} in region {region}: {e}")
        return warnings


    def check_s3_bucket_encryption_in_transit(self, bucket):
        """
        Ensure that the provided S3 bucket has a policy that enforces encryption in transit to safeguard data during transfer operations.
        """
        warnings = []
        bucket_name = bucket['Name']
        region = self._get_region_for_bucket(bucket_name)
        s3 = self.session.client('s3', region_name=region)
        try:
            response = s3.get_bucket_policy_status(Bucket=bucket_name)
            status = response['PolicyStatus']['IsPublic']
            if status:
                warning = {
                    "warning": f"S3 bucket {bucket_name} in region {region} has a public bucket policy",
                    "explanation": "Public bucket policies can potentially allow unauthorized access to data",
                    "recommendation": f"Review the bucket policy for {bucket_name} and adjust permissions if necessary"
                }
                warnings.append(warning)
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                logging.error(f"Error checking S3 bucket {bucket_name} in region {region}: {e}")
        return warnings


    def check_s3_logging_enabled(self, bucket):
        """
        Verify if logging is enabled for the provided S3 bucket, as logging is crucial for auditing and security purposes.
        """
        warnings = []
        bucket_name = bucket['Name']
        region = self._get_region_for_bucket(bucket_name)
        s3 = self.session.client('s3', region_name=region)
        try:
            logging_status = s3.get_bucket_logging(Bucket=bucket_name)
            if not logging_status or 'LoggingEnabled' not in logging_status:
                warning = {
                    "warning": f"S3 bucket {bucket_name} in region {region} does not have logging enabled",
                    "explanation": "Logging is crucial for auditing and security purposes",
                    "recommendation": f"Enable logging for {bucket_name} using the S3 console or the AWS CLI"
                }
                warnings.append(warning)
        except ClientError as e:
            logging.error(f"Error checking logging for S3 bucket {bucket_name} in region {region}: {e}")
        return warnings

    
    def get_all_warnings(self):
        all_warnings = []
        bucket_count = len(self.buckets)
        max_workers = min(cpu_count(), bucket_count)
        logging.info(f"Using {max_workers} workers for {bucket_count} buckets.")

        if max_workers == 0:
            return all_warnings

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_bucket = {
                executor.submit(self.check_s3_bucket_acl, bucket): bucket for bucket in self.buckets
            }
            future_to_bucket.update({
                executor.submit(self.check_s3_bucket_policy, bucket): bucket for bucket in self.buckets
            })
            future_to_bucket.update({
                executor.submit(self.check_s3_service_encryption, bucket): bucket for bucket in self.buckets
            })
            future_to_bucket.update({
                executor.submit(self.check_s3_object_ownership, bucket, "9641163299277"): bucket for bucket in self.buckets
            })
            future_to_bucket.update({
                executor.submit(self.check_s3_bucket_encryption_in_transit, bucket): bucket for bucket in self.buckets
            })
            future_to_bucket.update({
                executor.submit(self.check_s3_logging_enabled, bucket): bucket for bucket in self.buckets
            })

            for future in future_to_bucket:
                all_warnings.extend(future.result())
        
        return all_warnings



    def write_warnings_to_file(self, folder_path='./logs/'):
        warnings = self.get_all_warnings()
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        filename = os.path.join(folder_path, 's3_warnings.json')
        with open(filename, 'w') as f:
            json.dump(warnings, f, indent=4)  # This will format the JSON with an indentation of 4 spaces
        logging.info('Successfully created warnings file!')


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    checker = S3SecurityChecker()
    checker.write_warnings_to_file()
