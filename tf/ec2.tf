data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "demo" {
  name = "demo-ec2-${var.name}"

  tags = {
    Name = "demo-ec2-${var.name}"
  }

  ingress {
    from_port   = 22
    to_port     = 22
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

resource "aws_iam_role" "demo" {
  name = "demo-ec2-${var.name}"

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

resource "aws_iam_instance_profile" "demo" {
  name = aws_iam_role.demo.name
  role = aws_iam_role.demo.name
}

resource "aws_iam_role_policy_attachment" "demo" {
  role       = aws_iam_role.demo.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_instance" "demo" {
  instance_type               = "t3.small"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.demo.id]

  ami                  = data.aws_ami.ubuntu.id
  iam_instance_profile = aws_iam_instance_profile.demo.name

  tags = {
    Name = "demo-ec2-${var.name}"
  }

  user_data = <<-EOT
    #cloud-config
    packages:
      - unzip

    write_files:
      - path: /etc/vault-ssh-helper.d/config.hcl
        content: |
          vault_addr = "http://${aws_instance.vault.public_ip}:8200"
          ssh_mount_point = "ssh"
          namespace = "/"
          allowed_roles = "security"
          allowed_cidr_list = "0.0.0.0/0" # demo purposes

    runcmd:
      # install vault-ssh-helper
      - wget https://releases.hashicorp.com/vault-ssh-helper/0.2.1/vault-ssh-helper_0.2.1_linux_amd64.zip
      - unzip -q vault-ssh-helper_0.2.1_linux_amd64.zip -d /usr/local/bin
      - chmod 0755 /usr/local/bin/vault-ssh-helper
      - chown root:root /usr/local/bin/vault-ssh-helper
      - rm vault-ssh-helper_0.2.1_linux_amd64.zip

      # backup
      - cp /etc/pam.d/sshd /etc/pam.d/sshd.bk
      - cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bk

      # /etc/pam.d/sshd (these steps can vary depending on OS)
      - sed -i '/@include common-auth/a auth optional pam_unix.so not_set_pass use_first_pass nodelay' /etc/pam.d/sshd
      - sed -i '/@include common-auth/a auth requisite pam_exec.so quiet expose_authtok log=/tmp/vaultssh.log /usr/local/bin/vault-ssh-helper -dev -config=/etc/vault-ssh-helper.d/config.hcl' /etc/pam.d/sshd
      - sed -i 's/^@include common-auth/#&/' /etc/pam.d/sshd

      # /etc/ssh/sshd_config (these steps can vary depending on OS)
      - sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
      - sed -i 's/^KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config

      # restart sshd
      - systemctl restart sshd
  EOT
}
