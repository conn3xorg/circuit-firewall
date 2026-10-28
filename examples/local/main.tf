variable "port" {
  type    = number
  default = 2222
}

module "firewall" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  # Podman forwards 127.0.0.1:2222 to sshd's port 22 in the container.
  ssh_allow = ["22/tcp"]

  allow = [
    { port = "80/tcp" },
    { port = "443/tcp" },
    { port = "9100/tcp", from = "10.0.0.0/8" },
  ]
}
