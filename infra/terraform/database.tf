resource "aws_db_subnet_group" "reports" {
  name       = "reports-${var.environment}"
  subnet_ids = aws_subnet.public[*].id
}

resource "aws_db_instance" "reports" {
  identifier                  = "student-reports-${var.environment}"
  engine                      = "postgres"
  engine_version              = "16.3"
  instance_class              = var.db_instance_class
  allocated_storage           = 50
  username                    = "reports_admin"
  manage_master_user_password = true
  storage_encrypted           = true
  db_subnet_group_name        = aws_db_subnet_group.reports.name
  vpc_security_group_ids      = [aws_security_group.database.id]
  publicly_accessible         = var.db_publicly_accessible
  backup_retention_period     = 7
  deletion_protection         = true
}
