variable "name" {}
variable "vpc_id" {}
variable "subnet" {}
variable "open" {}
resource "aws_security_group" "web" {
  name   = var.name
  vpc_id = var.vpc_id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.open]
  }
}
resource "aws_instance" "web" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  subnet_id              = var.subnet
  vpc_security_group_ids = [aws_security_group.web.id]
}
