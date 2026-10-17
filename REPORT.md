# Scan report

| Stack | Resources | Passed | Failed | Skipped |
|---|---|---|---|---|
| insecure | 4 | 9 | 24 | 0 |
| hardened | 17 | 52 | 0 | 5 |

## Controls the insecure stack fails

- `CKV2_AWS_40` - Ensure AWS IAM policy does not allow full IAM privileges
- `CKV2_AWS_5` - Ensure that Security Groups are attached to another resource
- `CKV2_AWS_6` - Ensure that S3 bucket has a Public Access block
- `CKV2_AWS_61` - Ensure that an S3 bucket has a lifecycle configuration
- `CKV2_AWS_62` - Ensure S3 buckets should have event notifications enabled
- `CKV2_AWS_64` - Ensure KMS key Policy is defined
- `CKV2_CUSTOM_1` - Ensure every S3 bucket declares an Owner tag
- `CKV_AWS_144` - Ensure that S3 bucket has cross-region replication enabled
- `CKV_AWS_145` - Ensure that S3 buckets are encrypted with KMS by default
- `CKV_AWS_18` - Ensure the S3 bucket has access logging enabled
- `CKV_AWS_20` - S3 Bucket has an ACL defined which allows public READ access.
- `CKV_AWS_21` - Ensure all data stored in the S3 bucket have versioning enabled
- `CKV_AWS_23` - Ensure every security group and rule has a description
- `CKV_AWS_24` - Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
- `CKV_AWS_286` - Ensure IAM policies does not allow privilege escalation
- `CKV_AWS_287` - Ensure IAM policies does not allow credentials exposure
- `CKV_AWS_288` - Ensure IAM policies does not allow data exfiltration
- `CKV_AWS_289` - Ensure IAM policies does not allow permissions management / resource exposure without constraints
- `CKV_AWS_290` - Ensure IAM policies does not allow write access without constraints
- `CKV_AWS_355` - Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions
- `CKV_AWS_382` - Ensure no security groups allow egress from 0.0.0.0:0 to port -1
- `CKV_AWS_62` - Ensure IAM policies that allow full "*-*" administrative privileges are not created
- `CKV_AWS_63` - Ensure no IAM policies documents allow "*" as a statement's actions
- `CKV_AWS_7` - Ensure rotation for customer created CMKs is enabled

## Justified skips in the hardened stack

- `CKV2_AWS_62` on `aws_s3_bucket.logs` - Event notifications are not required on a log-only bucket
- `CKV2_AWS_62` on `aws_s3_bucket.data` - No downstream consumers need event notifications for this bucket
- `CKV_AWS_18` on `aws_s3_bucket.logs` - This IS the access-log destination; logging it to itself is circular
- `CKV_AWS_144` on `aws_s3_bucket.logs` - Cross-region replication of access logs is not justified by cost for this workload
- `CKV_AWS_144` on `aws_s3_bucket.data` - Cross-region replication is out of scope for this example and doubles storage cost
