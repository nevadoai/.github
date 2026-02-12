# Terraform SOC2 Compliance Policies
# These policies enforce SOC2 compliance requirements for AWS infrastructure
# Designed to align with Drata monitoring and SOC2 Trust Services Criteria
#
# Trust Services Criteria covered:
# - CC6.1: Logical and Physical Access Controls
# - CC6.6: System Monitoring
# - CC6.7: Infrastructure and Software Management
# - CC7.2: System Monitoring
# - A1.2: System Availability

package terraform

import rego.v1

#############################################################################
# SOC2 CC6.1 - Data Security & Encryption at Rest
# Requirement: Sensitive data must be encrypted at rest
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must have server-side encryption enabled for data at rest", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    not resource.storage_encrypted
    msg := sprintf("[SOC2-CC6.1] RDS instance '%s' must have storage encryption enabled for data at rest", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_ebs_volume[name]
    not resource.encrypted
    msg := sprintf("[SOC2-CC6.1] EBS volume '%s' must be encrypted for data at rest", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_instance[name]
    some device
    ebs := resource.ebs_block_device[device]
    not ebs.encrypted
    msg := sprintf("[SOC2-CC6.1] EC2 instance '%s' EBS volume must be encrypted for data at rest", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_dynamodb_table[name]
    not resource.server_side_encryption
    msg := sprintf("[SOC2-CC6.1] DynamoDB table '%s' must have encryption enabled for data at rest", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_efs_file_system[name]
    not resource.encrypted
    msg := sprintf("[SOC2-CC6.1] EFS file system '%s' must be encrypted for data at rest", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_eks_cluster[name]
    not resource.encryption_config
    msg := sprintf("[SOC2-CC6.1] EKS cluster '%s' must have secrets encryption enabled for data at rest", [name])
}

#############################################################################
# SOC2 CC6.1 - Data Security & Encryption in Transit
# Requirement: Data transmitted over public networks must be encrypted
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_lb_listener[name]
    resource.protocol == "HTTP"
    msg := sprintf("[SOC2-CC6.1] Load balancer listener '%s' must use HTTPS for encryption in transit", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_alb_listener[name]
    resource.protocol == "HTTP"
    msg := sprintf("[SOC2-CC6.1] ALB listener '%s' must use HTTPS for encryption in transit", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_api_gateway_stage[name]
    not resource.xray_tracing_enabled
    msg := sprintf("[SOC2-CC6.1] API Gateway stage '%s' should have X-Ray tracing enabled for monitoring", [name])
}

#############################################################################
# SOC2 CC6.1 - Access Control
# Requirement: Access to systems must be restricted to authorized users
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_security_group[name]
    some rule
    ingress := resource.ingress[rule]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    ingress.from_port == 22
    msg := sprintf("[SOC2-CC6.1] Security Group '%s' must not allow SSH (port 22) from 0.0.0.0/0 - violates access control requirements", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_security_group[name]
    some rule
    ingress := resource.ingress[rule]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    ingress.from_port == 3389
    msg := sprintf("[SOC2-CC6.1] Security Group '%s' must not allow RDP (port 3389) from 0.0.0.0/0 - violates access control requirements", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    resource.publicly_accessible == true
    msg := sprintf("[SOC2-CC6.1] RDS instance '%s' must not be publicly accessible - violates access control requirements", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.block_public_acls
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must block public ACLs - violates access control requirements", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.block_public_policy
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must block public policies - violates access control requirements", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.ignore_public_acls
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must ignore public ACLs - violates access control requirements", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.restrict_public_buckets
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must restrict public bucket policies - violates access control requirements", [name])
}

#############################################################################
# SOC2 CC6.1 - IAM & Least Privilege
# Requirement: Implement least privilege access control
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_iam_policy[name]
    policy_doc := json.unmarshal(resource.policy)
    some statement
    stmt := policy_doc.Statement[statement]
    stmt.Effect == "Allow"
    stmt.Action == "*"
    stmt.Resource == "*"
    msg := sprintf("[SOC2-CC6.1] IAM Policy '%s' violates least privilege - must not grant all actions (*) on all resources (*)", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_iam_role_policy[name]
    policy_doc := json.unmarshal(resource.policy)
    some statement
    stmt := policy_doc.Statement[statement]
    stmt.Effect == "Allow"
    stmt.Action == "*"
    stmt.Resource == "*"
    msg := sprintf("[SOC2-CC6.1] IAM Role Policy '%s' violates least privilege - must not grant all actions (*) on all resources (*)", [name])
}

warn contains msg if {
    some name
    resource := input.resource.aws_iam_user[name]
    msg := sprintf("[SOC2-CC6.1] IAM user '%s' detected - SOC2 best practice recommends using IAM roles with temporary credentials instead of long-lived user credentials", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_iam_access_key[name]
    msg := sprintf("[SOC2-CC6.1] IAM access key '%s' should not be managed in Terraform - use IAM Identity Center or temporary credentials", [name])
}

#############################################################################
# SOC2 CC6.6 & CC7.2 - Logging and Monitoring
# Requirement: System activities must be logged and monitored
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.logging
    not has_s3_bucket_logging(name)
    msg := sprintf("[SOC2-CC7.2] S3 bucket '%s' must have access logging enabled for audit trail", [name])
}

has_s3_bucket_logging(bucket_name) if {
    some name
    resource := input.resource.aws_s3_bucket_logging[name]
    resource.bucket == bucket_name
}

deny contains msg if {
    some name
    resource := input.resource.aws_cloudtrail[name]
    not resource.enable_logging
    msg := sprintf("[SOC2-CC7.2] CloudTrail '%s' must have logging enabled for audit trail", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_cloudtrail[name]
    not resource.is_multi_region_trail
    msg := sprintf("[SOC2-CC7.2] CloudTrail '%s' must be multi-region to capture all API activity", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_cloudtrail[name]
    not resource.enable_log_file_validation
    msg := sprintf("[SOC2-CC7.2] CloudTrail '%s' must have log file validation enabled for integrity", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_vpc[name]
    not has_flow_logs_for_vpc(name)
    msg := sprintf("[SOC2-CC7.2] VPC '%s' must have VPC Flow Logs enabled for network monitoring", [name])
}

has_flow_logs_for_vpc(vpc_name) if {
    some flow_log_name
    flow_log := input.resource.aws_flow_log[flow_log_name]
    flow_log.vpc_id == vpc_name
}

deny contains msg if {
    some name
    resource := input.resource.aws_instance[name]
    not resource.monitoring
    msg := sprintf("[SOC2-CC7.2] EC2 instance '%s' must have detailed monitoring enabled for system monitoring", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    not resource.enabled_cloudwatch_logs_exports
    msg := sprintf("[SOC2-CC7.2] RDS instance '%s' must export logs to CloudWatch for monitoring", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_lambda_function[name]
    not resource.tracing_config
    msg := sprintf("[SOC2-CC7.2] Lambda function '%s' must have X-Ray tracing enabled for monitoring", [name])
}

#############################################################################
# SOC2 A1.2 - Backup and Recovery (Availability)
# Requirement: Systems must have backup and recovery procedures
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.versioning
    not has_s3_versioning(name)
    msg := sprintf("[SOC2-A1.2] S3 bucket '%s' must have versioning enabled for data recovery", [name])
}

has_s3_versioning(bucket_name) if {
    some name
    resource := input.resource.aws_s3_bucket_versioning[name]
    resource.bucket == bucket_name
    resource.versioning_configuration[_].status == "Enabled"
}

deny contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    not resource.backup_retention_period
    msg := sprintf("[SOC2-A1.2] RDS instance '%s' must have automated backups enabled for data recovery", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    resource.backup_retention_period < 7
    msg := sprintf("[SOC2-A1.2] RDS instance '%s' must have backup retention period of at least 7 days", [name])
}

warn contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    not resource.multi_az
    msg := sprintf("[SOC2-A1.2] RDS instance '%s' should have multi-AZ enabled for high availability", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_dynamodb_table[name]
    not resource.point_in_time_recovery
    not has_dynamodb_pitr(name)
    msg := sprintf("[SOC2-A1.2] DynamoDB table '%s' must have point-in-time recovery enabled for data recovery", [name])
}

has_dynamodb_pitr(table_name) if {
    some name
    resource := input.resource.aws_dynamodb_table_point_in_time_recovery[name]
    resource.table_name == table_name
    resource.point_in_time_recovery[_].enabled
}

#############################################################################
# SOC2 CC6.1 - Secure Configuration
# Requirement: Systems must be securely configured
#############################################################################

deny contains msg if {
    some name
    resource := input.resource.aws_security_group[name]
    some rule
    ingress := resource.ingress[rule]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    ingress.protocol == "-1"
    msg := sprintf("[SOC2-CC6.1] Security Group '%s' must not allow all protocols from 0.0.0.0/0 - violates secure configuration", [name])
}

warn contains msg if {
    some name
    resource := input.resource.aws_instance[name]
    not resource.metadata_options
    msg := sprintf("[SOC2-CC6.1] EC2 instance '%s' should configure IMDSv2 (metadata_options with http_tokens = required)", [name])
}

warn contains msg if {
    some name
    resource := input.resource.aws_instance[name]
    some idx
    metadata := resource.metadata_options[idx]
    metadata.http_tokens != "required"
    msg := sprintf("[SOC2-CC6.1] EC2 instance '%s' should require IMDSv2 (http_tokens = required) for enhanced security", [name])
}

deny contains msg if {
    some name
    resource := input.resource.aws_eks_cluster[name]
    resource.vpc_config[_].endpoint_public_access == true
    not resource.vpc_config[_].public_access_cidrs
    msg := sprintf("[SOC2-CC6.1] EKS cluster '%s' with public endpoint must restrict access with public_access_cidrs", [name])
}

#############################################################################
# SOC2 CC6.7 - Change Management & Tagging
# Requirement: Resources must be properly tagged for change tracking
#############################################################################

warn contains msg if {
    some name
    resource := input.resource.aws_instance[name]
    not resource.tags
    msg := sprintf("[SOC2-CC6.7] EC2 instance '%s' should have tags for change management and resource tracking", [name])
}

warn contains msg if {
    some name
    resource := input.resource.aws_db_instance[name]
    not resource.tags
    msg := sprintf("[SOC2-CC6.7] RDS instance '%s' should have tags for change management and resource tracking", [name])
}

warn contains msg if {
    some name
    resource := input.resource.aws_s3_bucket[name]
    not resource.tags
    msg := sprintf("[SOC2-CC6.7] S3 bucket '%s' should have tags for change management and resource tracking", [name])
}

#############################################################################
# Drata-Specific Checks
# Additional checks that align with common Drata monitoring requirements
#############################################################################

# Ensure CloudTrail logs are sent to CloudWatch for Drata monitoring
warn contains msg if {
    some name
    resource := input.resource.aws_cloudtrail[name]
    not resource.cloud_watch_logs_group_arn
    msg := sprintf("[DRATA] CloudTrail '%s' should send logs to CloudWatch Logs for Drata monitoring", [name])
}

# Ensure GuardDuty is enabled for threat detection
warn contains msg if {
    count([x | input.resource.aws_guardduty_detector[x]]) == 0
    msg := "[DRATA] AWS GuardDuty detector should be enabled for threat detection and Drata monitoring"
}

# Ensure Config is enabled for compliance monitoring
warn contains msg if {
    count([x | input.resource.aws_config_configuration_recorder[x]]) == 0
    msg := "[DRATA] AWS Config should be enabled for continuous compliance monitoring with Drata"
}

# Ensure Security Hub is enabled for centralized security findings
warn contains msg if {
    count([x | input.resource.aws_securityhub_account[x]]) == 0
    msg := "[DRATA] AWS Security Hub should be enabled for centralized security findings and Drata integration"
}
