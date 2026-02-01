# =============================================================================
# Security Groups for NIST Multi-Agent Network
# =============================================================================

# Security Group for Lambda Functions
resource "aws_security_group" "lambda_sg" {
  name_prefix = "${var.project_name}-lambda-"
  vpc_id      = aws_vpc.nist_vpc.id
  description = "Security group for NIST Multi-Agent Lambda functions"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-lambda-sg"
    Type = "Lambda"
  })
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoint_sg" {
  name_prefix = "${var.project_name}-vpc-endpoint-"
  vpc_id      = aws_vpc.nist_vpc.id
  description = "Security group for VPC Endpoints (Bedrock Agent Runtime)"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-vpc-endpoint-sg"
    Type = "VPCEndpoint"
  })
}

# Security Group Rules (separate resources to avoid circular dependency)

# Lambda SG - Outbound rule: HTTPS to internet (for AWS API calls)
resource "aws_security_group_rule" "lambda_egress_internet" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.lambda_sg.id
  description       = "HTTPS to internet for AWS API calls"
}

# Lambda SG - Outbound rule: HTTPS to VPC Endpoint
resource "aws_security_group_rule" "lambda_egress_vpc_endpoint" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpc_endpoint_sg.id
  security_group_id        = aws_security_group.lambda_sg.id
  description              = "HTTPS to VPC Endpoint for Bedrock Agent Runtime"
}

# VPC Endpoint SG - Inbound rule: HTTPS from Lambda Security Group
resource "aws_security_group_rule" "vpc_endpoint_ingress_lambda" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda_sg.id
  security_group_id        = aws_security_group.vpc_endpoint_sg.id
  description              = "HTTPS from Lambda functions"
}

# VPC Endpoint SG - Outbound rule: All traffic (default for VPC endpoints)
resource "aws_security_group_rule" "vpc_endpoint_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.vpc_endpoint_sg.id
  description       = "All outbound traffic"
}
