output "Ubuntu-Redirector-Server-IP" {
  description = "The public IP address for the Ubuntu Redirector Server."
  value       = aws_instance.redirector-server.public_ip
}

output "Ubuntu-cnc-Server-Private-IP" {
  description = "The private IP address for the Ubuntu C2 Server."
  value       = aws_instance.cnc-server.private_ip
}

output "c2_ssh_command_via_jump" {
  description = "SSH command to connect to the C2 Server via jump host"
  value       = "ssh -A -J ubuntu@${aws_instance.redirector-server.public_ip} -i ${aws_key_pair.kp.key_name}.pem ubuntu@${aws_instance.cnc-server.private_ip}"
}

output "redirector_ssh_command" {
  description = "SSH command to connect to the Ubuntu Redirector Server"
  value       = "ssh -A -i ${aws_key_pair.kp.key_name}.pem ubuntu@${aws_instance.redirector-server.public_ip}"
}
