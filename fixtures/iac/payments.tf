# Payments service - staging stack

resource "aws_s3_bucket" "receipts" {
  bucket = "acme-payments-receipts"
  acl    = "public-read"

  tags = {
    Team = "payments"
  }
}

resource "aws_security_group" "app" {
  name        = "payments-app"
  description = "Payments API and database access"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH for debugging"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "ledger" {
  identifier             = "payments-ledger"
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  username               = var.db_username
  password               = var.db_password
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.app.id]
}

resource "aws_instance" "api" {
  ami                    = var.api_ami
  instance_type          = "t3.small"
  vpc_security_group_ids = [aws_security_group.app.id]
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "eu-west-1a"
  size              = 100
}

variable "vpc_id" {
  type = string
}

variable "api_ami" {
  type = string
}

variable "db_username" {
  type = string
}

variable "db_password" {
  type      = string
  sensitive = true
}
