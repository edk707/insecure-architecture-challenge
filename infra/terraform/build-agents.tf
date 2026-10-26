# Self-hosted CI runners. Builds should only reach the internal package proxy.

resource "aws_security_group" "build_agents" {
  name        = "ci-build-agents"
  description = "Self-hosted CI runners"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Runner control plane"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Package proxy"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.package_proxy_cidr]
  }
}
