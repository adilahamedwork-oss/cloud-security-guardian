# 🛡️ Cloud Security Guardian

An AWS-based cloud security monitoring prototype that checks Amazon S3 bucket security configurations, classifies security findings, stores results in DynamoDB, and supports scheduled scanning with Amazon EventBridge Scheduler.

## 📌 Project Overview

Cloud Security Guardian demonstrates how AWS services can be combined to build a simple serverless cloud security monitoring workflow. It is designed as a hands-on cloud security project for learning AWS, serverless computing, security configuration checks, and automated findings storage.

## 🏗️ Architecture

```text
Amazon EventBridge Scheduler
             |
             | Scheduled invocation
             v
      AWS Lambda Function
    cloud-guardian-handler
             |
             +------> Amazon S3
             |        Check bucket security configuration
             |
             +------> Amazon DynamoDB
                      Store security findings
```

## ☁️ AWS Services Used

| Service                      | Purpose                                                               |
| ---------------------------- | --------------------------------------------------------------------- |
| AWS Lambda                   | Runs the security scanning and finding-processing logic               |
| Amazon S3                    | Resource checked by the S3 security scan                              |
| Amazon DynamoDB              | Stores findings for later review                                      |
| Amazon EventBridge Scheduler | Configured to invoke the Lambda function daily                        |
| Amazon CloudWatch Logs       | Records execution output for troubleshooting and verification         |
| AWS IAM                      | Controls permissions for the Lambda function and scheduled invocation |

## 🔍 Security Checks and Finding Classification

The S3 scan checks the bucket's Block Public Access configuration and whether its bucket policy is classified as public.

The prototype also supports simulated findings with these severity mappings:

| Finding type          | Severity |
| --------------------- | -------- |
| Public S3             | CRITICAL |
| Overly permissive IAM | HIGH     |
| Open security group   | HIGH     |
| Unencrypted storage   | MEDIUM   |
| Missing logs          | MEDIUM   |

These simulated findings demonstrate the finding-processing workflow; they do not mean the prototype automatically scans every AWS resource for those conditions.

## ⚙️ Workflow

1. A test event or scheduled invocation triggers the Lambda function.
2. For an S3 scan, the function checks the specified bucket's public-access settings and bucket policy status.
3. The function assigns a severity and creates a finding result.
4. The finding is assigned a unique ID and written to DynamoDB.
5. CloudWatch Logs records execution output to help troubleshoot and verify behavior.

## 🧪 Validation Performed

* Successfully executed the Lambda S3 scan test.
* Verified that the test bucket had Block Public Access enabled and its bucket policy was not classified as public.
* Successfully tested a simulated open-security-group finding with HIGH severity.
* Verified that three items were present in the DynamoDB findings table.
* Created and enabled a daily EventBridge schedule targeting the Lambda function. Successful automatic scheduled execution remains to be verified.

## 🧰 Technology Stack

* AWS Lambda
* Amazon S3
* Amazon DynamoDB
* Amazon EventBridge Scheduler
* Amazon CloudWatch
* AWS IAM
* Python
* Boto3

## 🚀 Setup Summary

This project was configured through the AWS Management Console in the `ap-southeast-2` region.

To reproduce it:

1. Create an S3 test bucket with Block Public Access enabled.
2. Create a DynamoDB table for findings, using a string partition key named `finding_id`.
3. Create a Python Lambda function with the required S3 and DynamoDB permissions.
4. Configure the function to check the test bucket and save results to DynamoDB.
5. Create an EventBridge schedule that invokes the Lambda function with an input event such as:

```json
{
  "action": "scan_s3",
  "bucket_name": "YOUR_TEST_BUCKET_NAME"
}
```

6. Review execution output in CloudWatch Logs and confirm stored findings in DynamoDB.

Use your own resource names and configure IAM permissions according to least-privilege principles. Do not use a personal portfolio bucket or any production resource for testing.

## 🔐 Security Notes

* Never commit AWS access keys, secret keys, session tokens, or other credentials.
* Use a dedicated test bucket.
* Keep S3 Block Public Access enabled during normal testing.
* Restrict IAM permissions to the resources and actions required.
* This is a learning prototype, not a production-grade cloud security platform.

## 🎯 Learning Outcomes

* Building a serverless workflow with AWS Lambda
* Checking S3 public-access configuration
* Writing structured findings to DynamoDB
* Configuring scheduled invocations with EventBridge Scheduler
* Using CloudWatch Logs for troubleshooting
* Understanding IAM permissions and least-privilege design

## 👨‍💻 Author

**Adil Ahamed**

Cloud Security | AWS | Cloud Engineering | Cybersecurity

---

*Built as a hands-on cloud security learning project.*
