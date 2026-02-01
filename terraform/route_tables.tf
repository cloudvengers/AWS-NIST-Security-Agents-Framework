# =============================================================================
# Route Tables for NIST Multi-Agent Network
# =============================================================================

# Public Route Table (for Public Subnets)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.nist_vpc.id

  # Route to Internet Gateway for internet access
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-public-rt"
    Type = "Public"
  })
}

# Private Route Table for us-east-1a (Lambda functions)
resource "aws_route_table" "private_1a" {
  vpc_id = aws_vpc.nist_vpc.id

  # Route to NAT Gateway for outbound internet access
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_1a.id
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-private-rt-1a"
    Type = "Private"
    AZ   = "us-east-1a"
  })
}

# Private Route Table for us-east-1c (Lambda functions)
resource "aws_route_table" "private_1c" {
  vpc_id = aws_vpc.nist_vpc.id

  # Route to NAT Gateway for outbound internet access
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_1c.id
  }

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-private-rt-1c"
    Type = "Private"
    AZ   = "us-east-1c"
  })
}

# Route Table Associations - Public Subnets
resource "aws_route_table_association" "public_1a" {
  subnet_id      = aws_subnet.public_1a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_1c" {
  subnet_id      = aws_subnet.public_1c.id
  route_table_id = aws_route_table.public.id
}

# Route Table Associations - Private Subnets
resource "aws_route_table_association" "private_1a" {
  subnet_id      = aws_subnet.private_1a.id
  route_table_id = aws_route_table.private_1a.id
}

resource "aws_route_table_association" "private_1c" {
  subnet_id      = aws_subnet.private_1c.id
  route_table_id = aws_route_table.private_1c.id
}
