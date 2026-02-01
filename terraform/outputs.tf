# =============================================================================
# Outputs for NIST Multi-Agent VPC Network
# =============================================================================

# VPC Information
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.nist_vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.nist_vpc.cidr_block
}

# Subnet Information
output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value = [
    aws_subnet.public_1a.id,
    aws_subnet.public_1c.id
  ]
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (for Lambda functions)"
  value = [
    aws_subnet.private_1a.id,
    aws_subnet.private_1c.id
  ]
}

output "private_subnet_1a_id" {
  description = "ID of the private subnet in us-east-1a"
  value       = aws_subnet.private_1a.id
}

output "private_subnet_1c_id" {
  description = "ID of the private subnet in us-east-1c"
  value       = aws_subnet.private_1c.id
}

# Security Group Information
output "lambda_security_group_id" {
  description = "ID of the Lambda security group"
  value       = aws_security_group.lambda_sg.id
}

output "vpc_endpoint_security_group_id" {
  description = "ID of the VPC endpoint security group"
  value       = aws_security_group.vpc_endpoint_sg.id
}

# Gateway Information
output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.igw.id
}

output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways"
  value = [
    aws_nat_gateway.nat_1a.id,
    aws_nat_gateway.nat_1c.id
  ]
}

output "nat_gateway_public_ips" {
  description = "Public IP addresses of the NAT Gateways"
  value = [
    aws_eip.nat_1a.public_ip,
    aws_eip.nat_1c.public_ip
  ]
}

# VPC Endpoint Information
output "bedrock_agent_runtime_endpoint_id" {
  description = "ID of the Bedrock Agent Runtime VPC endpoint"
  value       = aws_vpc_endpoint.bedrock_agent_runtime.id
}

output "bedrock_agent_runtime_endpoint_dns_names" {
  description = "DNS names of the Bedrock Agent Runtime VPC endpoint"
  value       = aws_vpc_endpoint.bedrock_agent_runtime.dns_entry[*].dns_name
}

# Route Table Information
output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_ids" {
  description = "IDs of the private route tables"
  value = [
    aws_route_table.private_1a.id,
    aws_route_table.private_1c.id
  ]
}

# Summary Information for Lambda Configuration
output "lambda_vpc_config" {
  description = "VPC configuration for Lambda functions"
  value = {
    subnet_ids         = [aws_subnet.private_1a.id, aws_subnet.private_1c.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
}
