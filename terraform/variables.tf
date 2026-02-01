# =============================================================================
# Variables for NIST Multi-Agent VPC Network
# =============================================================================

# Common tags to be applied to all resources
variable "common_tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "nist-security-analysis"
    Purpose     = "multi-agent-vpc"
    Owner       = "security-team"
    ManagedBy   = "terraform"
  }
}

# AWS Region
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

# Project name for resource naming
variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "nist-multi-agent"
}
