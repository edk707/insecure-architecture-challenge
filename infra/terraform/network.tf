resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  count      = 2
  vpc_id     = aws_vpc.main.id
  cidr_block = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
}

# Application load balancer -> pods. HTTPS out is needed for AWS APIs.
resource "aws_security_group" "app" {
  name   = "reports-app"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "From the load balancer"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS to AWS service endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "database" {
  name   = "reports-db"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "Postgres from the app only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

# Added during the self-hosted runner migration (ticket PLAT-412).
resource "aws_vpc_security_group_egress_rule" "build_agents_bootstrap" {
  security_group_id = aws_security_group.build_agents.id
  description       = "Temporary: runner bootstrap"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
