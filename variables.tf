variable "AWS_REGION" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-west-2"
}

variable "AVAILABILITY_ZONE" {
  description = "AWS Availability Zone"
  type        = string
  default     = "us-west-2a"
  validation {
    condition     = contains(["us-west-2a", "us-west-2b", "us-west-2c", "us-west-2d"], var.AVAILABILITY_ZONE)
    error_message = "Availability zone must be one of: us-west-2a, us-west-2b, us-west-2c, us-west-2d."
  }
}

variable "c2_domain" {  
  description = "FQDN of your site, like: example.com"  
  type        = string
}
