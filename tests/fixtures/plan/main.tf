provider "aws" {
  region                      = "eu-west-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
variable "public" { default = true }
variable "envs" { default = ["a", "b"] }
resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }
resource "aws_subnet" "pub" {
  count                   = 2
  vpc_id                  = aws_vpc.v.id
  cidr_block              = "10.0.${count.index}.0/24"
  map_public_ip_on_launch = var.public
}
resource "aws_s3_bucket" "unused" {
  count  = 0
  bucket = "never"
}
module "web" {
  source   = "./modules/web"
  for_each = toset(var.envs)
  name     = each.key
  vpc_id   = aws_vpc.v.id
  subnet   = aws_subnet.pub[0].id
  open     = var.public ? "0.0.0.0/0" : "10.0.0.0/8"
}
