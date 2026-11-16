# Internal load balancer security group

resource "aws_security_group" "internal_lb" {
  name   = "internal-lb"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_ebs_volume" "cache" {
  availability_zone = "eu-west-1b"
  size              = 20
  encrypted         = true
}

variable "vpc_id" {
  type = string
}
