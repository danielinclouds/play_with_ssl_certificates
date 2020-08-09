variable "cert_arn" {
  type = string
  description = "ARN of the certificate in AWS Cert Manager"
}

variable "dns_record" {
  type = string
  description = "example: www.example.com"
}

variable "zone_id" {
  type = string
  description = "example: ZJLABC1234"
}




provider "aws" {
  region = "eu-west-2"
}


# -----------------------------
# SSH
# -----------------------------
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
}

resource "local_file" "file_ssh_key_priv" {
  content         = tls_private_key.ssh_key.private_key_pem
  filename        = "${path.module}/key.pem"
  file_permission = "0600"
}

resource "local_file" "file_ssh_key_pub" {
  content         = tls_private_key.ssh_key.public_key_openssh
  filename        = "${path.module}/key.pem.pub"
}

resource "aws_key_pair" "ssh_key" {
  key_name   = "ssh-key"
  public_key = tls_private_key.ssh_key.public_key_openssh
}


# -----------------------------
# Networking
# -----------------------------
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "test-server-vpc"
  cidr = "10.0.0.0/16"

  azs            = ["eu-west-2a", "eu-west-2b"]
  public_subnets = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway = true

  tags = {
    Terraform = "true"
    Notes     = "delete-me"
  }
}

resource "aws_security_group" "allow_all_public" {
  name        = "allow_all_public"
  description = "Allow All inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# -----------------------------
# LB
# -----------------------------
resource "aws_lb" "lb" {
  name               = "lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.allow_all_public.id]
  subnets            = module.vpc.public_subnets
  ip_address_type    = "ipv4"

  enable_deletion_protection = false

}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.cert_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_lb_target_group" "tg" {
  name     = "tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id
}

resource "aws_lb_target_group_attachment" "tg-attachment" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.public_server.id
  port             = 80
}

resource "aws_route53_record" "www" {
  zone_id = var.zone_id
  name    = var.dns_record
  type    = "A"

  alias {
    name                   = aws_lb.lb.dns_name
    zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = false
  }
}


# -----------------------------
# Instance
# -----------------------------
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "public_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.ssh_key.key_name
  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.allow_all_public.id]
  
  user_data = <<-EOF
		#! /bin/bash
    sudo apt-get update
		sudo apt-get install -y nginx


	EOF


  tags = {
    Terraform = "true"
    Notes     = "delete-me"
  }
}


# -----------------------------
# Outputs
# -----------------------------
output "public_instance_public_ip" {
  value = aws_instance.public_server.public_ip
}

output "instance_username" {
  value = "ubuntu"
}

output "public_instance_connection_string" {
  value = "ssh -i key.pem ubuntu@${aws_instance.public_server.public_ip}"
}
