import json
import boto3
import uuid
from datetime import datetime, timezone
from botocore.exceptions import ClientError

AWS_REGION = "ap-southeast-2"
TABLE_NAME = "CloudSecrityfindings"

s3 = boto3.client("s3", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)


def save_finding(result):
    item = dict(result)
    item["finding_id"] = str(uuid.uuid4())
    table.put_item(Item=item)
    return item["finding_id"]


def lambda_handler(event, context):
    event = event or {}

    if event.get("action") == "scan_s3":
        bucket_name = event.get("bucket_name")

        if not bucket_name:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "Please provide a bucket_name."
                })
            }

        try:
            response = s3.get_public_access_block(
                Bucket=bucket_name
            )
            public_access = response[
                "PublicAccessBlockConfiguration"
            ]

            policy_is_public = False

            try:
                policy_response = s3.get_bucket_policy_status(
                    Bucket=bucket_name
                )
                policy_is_public = policy_response[
                    "PolicyStatus"
                ]["IsPublic"]

            except ClientError as error:
                code = error.response["Error"]["Code"]
                if code not in (
                    "NoSuchBucketPolicy",
                    "NoSuchBucketPolicyStatus"
                ):
                    raise

            block_keys = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets"
            ]

            all_block_settings_on = all(
                public_access.get(key, False)
                for key in block_keys
            )

            if policy_is_public:
                severity = "HIGH"
                finding = "Bucket policy allows public access"
            elif not all_block_settings_on:
                severity = "MEDIUM"
                finding = (
                    "Block Public Access is not fully enabled"
                )
            else:
                severity = "LOW"
                finding = (
                    "No public access issue detected by these checks"
                )

            result = {
                "project": "Cloud Security Guardian",
                "scan_type": "S3 security configuration",
                "bucket": bucket_name,
                "block_public_access": all_block_settings_on,
                "bucket_policy_is_public": policy_is_public,
                "severity": severity,
                "finding": finding,
                "detected_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "status": "CHECKED"
            }

        except ClientError as error:
            print("S3 scan failed:", str(error))
            return {
                "statusCode": 500,
                "body": json.dumps({
                    "error": error.response["Error"]["Code"],
                    "message": (
                        "S3 scan failed. Check the bucket name "
                        "and permissions."
                    ),
                    "bucket": bucket_name
                })
            }

    else:
        finding_type = str(
            event.get("finding_type", "unknown")
        ).lower().strip()

        resource_id = str(
            event.get("resource_id", "unknown")
        )

        description = str(
            event.get(
                "description",
                "No description provided"
            )
        )

        severity_map = {
            "public_s3": "CRITICAL",
            "overly_permissive_iam": "HIGH",
            "open_security_group": "HIGH",
            "unencrypted_storage": "MEDIUM",
            "missing_logs": "MEDIUM"
        }

        remediation_map = {
            "public_s3": (
                "Review S3 bucket public access settings."
            ),
            "overly_permissive_iam": (
                "Apply least-privilege IAM permissions."
            ),
            "open_security_group": (
                "Restrict inbound rules to trusted sources."
            ),
            "unencrypted_storage": (
                "Enable encryption at rest."
            ),
            "missing_logs": (
                "Enable appropriate logging and monitoring."
            )
        }

        result = {
            "project": "Cloud Security Guardian",
            "finding_type": finding_type,
            "resource_id": resource_id,
            "severity": severity_map.get(
                finding_type, "LOW"
            ),
            "description": description,
            "detected_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "status": "DETECTED",
            "remediation": remediation_map.get(
                finding_type,
                "Investigate this finding and review the resource configuration."
            )
        }

    try:
        finding_id = save_finding(result)
        result["finding_id"] = finding_id

        print(json.dumps(result))

        return {
            "statusCode": 200,
            "body": json.dumps(result)
        }

    except ClientError as error:
        print("DynamoDB save failed:", str(error))

        return {
            "statusCode": 500,
            "body": json.dumps({
                "project": "Cloud Security Guardian",
                "error": error.response["Error"]["Code"],
                "message": (
                    "Finding could not be saved to DynamoDB. "
                    "Check the table name, region, and "
                    "Lambda execution-role permissions."
                )
            })
        }
