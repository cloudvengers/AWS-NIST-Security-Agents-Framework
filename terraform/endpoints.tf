# =============================================================================
# VPC Endpoints for NIST Multi-Agent Network
# =============================================================================

# VPC Endpoint for Bedrock Agent Runtime API
resource "aws_vpc_endpoint" "bedrock_agent_runtime" {
  vpc_id              = aws_vpc.nist_vpc.id
  service_name        = "com.amazonaws.us-east-1.bedrock-agent-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_1a.id, aws_subnet.private_1c.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  # Enable private DNS resolution
  private_dns_enabled = true
  
  # Policy to allow access from Lambda functions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "bedrock:InvokeAgent",
          "bedrock:InvokeAgentWithResponseStream"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalVpc" = aws_vpc.nist_vpc.id
          }
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-bedrock-agent-runtime-endpoint"
    Service = "bedrock-agent-runtime"
    Type    = "Interface"
  })
}
