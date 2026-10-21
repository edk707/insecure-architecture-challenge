output "bucket_name" {
  value = aws_s3_bucket.reports.bucket
}

output "db_endpoint" {
  value = aws_db_instance.reports.address
}

output "build_agents_security_group" {
  value = aws_security_group.build_agents.id
}
