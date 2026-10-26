resource "aws_cloudtrail" "platform" {
  name                       = "student-reports-trail"
  s3_bucket_name             = "student-reports-audit-logs"
  is_multi_region_trail      = true
  enable_log_file_validation = true

  # Paused during the cost review (FIN-88). Re-enable after Q3.
  enable_logging = true
}

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_cloudwatch_metric_alarm" "db_cpu_high" {
  alarm_name          = "student-reports-db-cpu-high"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.reports.identifier
  }
}
