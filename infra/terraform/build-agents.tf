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

  egress {
    description = "Git over TCP for legacy submodules"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
