variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file or jump_hosts."
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}


variable "ssh_allow" {
  type        = list(string)
  default     = null
  description = "Ports sshd listens on, which stay open before the firewall turns on, such as [\"22/tcp\"]. When null, the ports Conn3x logs in on. Set it when a port forward or NAT sits between Conn3x and the hosts."

  validation {
    condition     = var.ssh_allow == null || length(coalesce(var.ssh_allow, ["-"])) > 0
    error_message = "ssh_allow can't be empty, or turning the firewall on would cut SSH. Leave it null to use the ports Conn3x logs in on."
  }
}

variable "allow" {
  type = list(object({
    port = string
    from = optional(string)
  }))
  default     = []
  description = "Ports to open, each with its protocol, such as { port = \"443/tcp\" }, or { port = \"5432/tcp\", from = \"10.0.0.0/8\" } to open it to one address or network only."

  validation {
    condition     = alltrue([for r in var.allow : can(regex("^[0-9]+(:[0-9]+)?/(tcp|udp)$", r.port))])
    error_message = "Each port needs a protocol, such as \"443/tcp\" or \"6000:6007/udp\"."
  }

  validation {
    condition     = alltrue([for r in var.allow : r.from == null || can(regex("^[0-9a-fA-F.:]+(/[0-9]{1,3})?$", coalesce(r.from, "-")))])
    error_message = "from must be an IP address or a CIDR network, such as \"10.0.0.0/8\"."
  }
}
