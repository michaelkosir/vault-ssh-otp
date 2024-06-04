#cloud-config
packages:
  - unzip

write_files:
  - path: /etc/vault-ssh-helper.d/config.hcl
    content: |
      vault_addr = "${vault_address}"
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
