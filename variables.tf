variable "vpc-cidr" {
  default = "10.0.0.0/16"
}

variable "subnet-cidr" {
  type    = list(any)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "instance-type" {
  type    = list(any)
  default = ["t2.micro", "t2.xlarge"]
}

variable "availability-zone" {
  default = ["us-east-1a", "us-east-1b"]
}