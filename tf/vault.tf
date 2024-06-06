resource "random_uuid" "this" {}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "vault" {
  name = "demo-vault-${var.name}"

  tags = {
    Name = "demo-vault-${var.name}"
  }

  ingress {
    from_port   = 8200
    to_port     = 8200
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

resource "aws_iam_role" "vault" {
  name = "demo-vault-${var.name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "vault" {
  name = aws_iam_role.vault.name
  role = aws_iam_role.vault.name
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.vault.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_instance" "vault" {
  instance_type               = "t3.small"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.vault.id]

  ami                  = data.aws_ami.al2023.id
  iam_instance_profile = aws_iam_instance_profile.vault.name

  tags = {
    Name = "demo-vault-${var.name}"
  }

  user_data = <<-EOT
    #cloud-config
    runcmd:
      - yum install -y yum-utils
      - yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
      - yum -y install vault
      - sed -i 's|^ExecStart.*$|ExecStart=/usr/bin/vault server -dev -dev-root-token-id=${random_uuid.this.result} -dev-listen-address=0.0.0.0:8200 -dev-no-store-token|' /lib/systemd/system/vault.service
      - systemctl daemon-reload
      - systemctl enable vault --now
  EOT
}
