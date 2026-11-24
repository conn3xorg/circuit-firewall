# Facts give each host's family: ufw on Debian and Ubuntu, firewalld on
# the Red Hat family.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os     = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  family = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) ? "debian" : "redhat" }

  # SSH stays open on every port Conn3x logs in on, so turning the
  # firewall on can't cut the connection. Behind a port forward, the port
  # sshd listens on differs, and ssh_allow names it.
  ssh_ports = toset(coalesce(var.ssh_allow, [for h in var.hosts : "${try(h.port, var.ssh_port)}/tcp"]))

  rules = { for r in var.allow : "${r.port} from ${coalesce(r.from, "anywhere")}" => r }
  # firewalld opens a port to everyone with --add-port, and to one
  # network with a rich rule.
  rich = {
    for k, r in local.rules : k => format(
      "rule family=%s source address=%s port port=%s protocol=%s accept",
      strcontains(r.from, ":") ? "ipv6" : "ipv4", r.from, replace(split("/", r.port)[0], ":", "-"), split("/", r.port)[1],
    ) if r.from != null
  }

  # Empty when default_zone is null, so firewalld's own default zone is used.
  zone_opt = var.default_zone == null ? "" : "--zone=${var.default_zone} "

  ufw_hosts       = { for name, h in var.hosts : name => h if local.family[name] == "debian" }
  firewalld_hosts = { for name, h in var.hosts : name => h if local.family[name] == "redhat" }
}

circuit "ufw" {
  hosts = local.ufw_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "package" {
    package {
      name = "ufw"
    }
  }

  step "ssh" {
    for_each = local.ssh_ports
    ufw {
      action = "allow"
      port   = item.value
    }
  }

  step "rules" {
    for_each = local.rules
    ufw {
      action = "allow"
      port   = item.value.port
      from   = item.value.from
    }
  }

  step "default_deny" {
    command {
      command = "ufw default deny incoming"
      unless  = "grep -qx 'DEFAULT_INPUT_POLICY=\"DROP\"' /etc/default/ufw"
    }
  }

  step "enabled" {
    command {
      command = "ufw --force enable"
      unless  = "ufw status | grep -qx 'Status: active'"
    }
  }
}

circuit "firewalld" {
  hosts = local.firewalld_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "package" {
    package {
      name = "firewalld"
    }
  }

  # The order keeps SSH open at every step. firewalld starts with the
  # default zone's rules, which allow SSH on port 22 in public. SSH on
  # another port is opened in default_zone before firewalld starts, and
  # SSH is open in default_zone before it becomes the default, so neither
  # starting firewalld nor switching zones can cut the connection.
  step "ssh_before_start" {
    for_each = setsubtract(local.ssh_ports, ["22/tcp"])
    command {
      command = "firewall-offline-cmd -q ${local.zone_opt}--add-port=${item.value}"
      unless  = "firewall-offline-cmd -q ${local.zone_opt}--query-port=${item.value}"
    }
  }

  step "running" {
    service {
      name    = "firewalld"
      state   = "started"
      enabled = true
    }
  }

  step "ssh" {
    for_each = local.ssh_ports
    firewalld {
      zone = var.default_zone
      port = item.value
    }
  }

  # Some images ship a default zone of trusted, which accepts everything,
  # such as Google Cloud's Rocky Linux. --set-default-zone changes the
  # running firewall and the permanent one.
  step "default_zone" {
    for_each = var.default_zone == null ? toset([]) : toset([var.default_zone])
    command {
      command = "firewall-cmd -q --set-default-zone=${item.value}"
      unless  = "[ \"$(firewall-cmd --get-default-zone)\" = ${item.value} ]"
    }
  }

  step "rules" {
    for_each = { for k, r in local.rules : k => r if r.from == null }
    firewalld {
      zone = var.default_zone
      # firewalld writes a range as 6000-6007, ufw as 6000:6007.
      port = replace(item.value.port, ":", "-")
    }
  }

  step "rich_rules" {
    for_each = local.rich
    command {
      command = "firewall-cmd -q ${local.zone_opt}--add-rich-rule='${item.value}' && firewall-cmd -q --permanent ${local.zone_opt}--add-rich-rule='${item.value}'"
      unless  = "firewall-cmd -q ${local.zone_opt}--query-rich-rule='${item.value}' && firewall-cmd -q --permanent ${local.zone_opt}--query-rich-rule='${item.value}'"
    }
  }
}
