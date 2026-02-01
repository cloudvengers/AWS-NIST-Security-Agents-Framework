# =============================================================================
# VPC, Subnets, and Gateways for NIST Multi-Agent Network
# =============================================================================

# VPC
resource "aws_vpc" "nist_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-vpc"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.nist_vpc.id

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-igw"
  })
}

# Public Subnets (for NAT Gateways)
resource "aws_subnet" "public_1a" {
  vpc_id                  = aws_vpc.nist_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-public-1a"
    Type = "Public"
    AZ   = "us-east-1a"
  })
}

resource "aws_subnet" "public_1c" {
  vpc_id                  = aws_vpc.nist_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1c"
  map_public_ip_on_launch = true

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-public-1c"
    Type = "Public"
    AZ   = "us-east-1c"
  })
}

# Private Subnets (for Lambda functions)
resource "aws_subnet" "private_1a" {
  vpc_id            = aws_vpc.nist_vpc.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1a"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-private-1a"
    Type = "Private"
    AZ   = "us-east-1a"
  })
}

resource "aws_subnet" "private_1c" {
  vpc_id            = aws_vpc.nist_vpc.id
  cidr_block        = "10.0.12.0/24"
  availability_zone = "us-east-1c"

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-private-1c"
    Type = "Private"
    AZ   = "us-east-1c"
  })
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat_1a" {
  domain = "vpc"
  
  depends_on = [aws_internet_gateway.igw]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-nat-eip-1a"
    AZ   = "us-east-1a"
  })
}

resource "aws_eip" "nat_1c" {
  domain = "vpc"
  
  depends_on = [aws_internet_gateway.igw]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-nat-eip-1c"
    AZ   = "us-east-1c"
  })
}

# NAT Gateways
resource "aws_nat_gateway" "nat_1a" {
  allocation_id = aws_eip.nat_1a.id
  subnet_id     = aws_subnet.public_1a.id

  depends_on = [aws_internet_gateway.igw]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-nat-1a"
    AZ   = "us-east-1a"
  })
}

resource "aws_nat_gateway" "nat_1c" {
  allocation_id = aws_eip.nat_1c.id
  subnet_id     = aws_subnet.public_1c.id

  depends_on = [aws_internet_gateway.igw]

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-nat-1c"
    AZ   = "us-east-1c"
  })
}
