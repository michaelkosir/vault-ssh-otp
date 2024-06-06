output "vault_addr" {
  value = "http://${aws_instance.vault.public_ip}:8200"
}

output "vault_token" {
  value = random_uuid.this.result
}

output "demo_ip" {
  value = aws_instance.demo.public_ip
}
