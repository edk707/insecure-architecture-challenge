variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.medium"
}

variable "db_publicly_accessible" {
  type        = bool
  description = "Lets the reporting team connect BI tools during the pilot"
  default     = false
}

variable "package_proxy_cidr" {
  type    = string
  default = "10.20.50.10/32"
}
