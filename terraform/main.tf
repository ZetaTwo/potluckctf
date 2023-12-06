# TODO: assign static ip to scoreboard
# TODO: firewall for monitor server
# TODO: firewall for scoreboard server
# TODO: server hostname not currently used
# TODO: output ansible inventory

provider "google-beta" {
  project = "potluck-ctf"
  region  = "europe-west3"
  zone    = "europe-west3-b"
}

terraform {
  required_version = ">= 1.4.4"
}

locals {
  server_settings = {
    scoreboard = {
      "scoreboard-a" = { hostname = "scoreboard.livectf.local", ip = "10.0.0.10", type = "e2-standard-8", labels = { bastion = 1 } },
    }
    challenges = {
      "challenge01" = {
        subnet = "10.0.1.0/24",
        servers = {
          "challenge01-a" = { hostname = "a.challenge01.potluckctf.local", ip = "10.0.1.10", type = "e2-standard-2", labels = { challenge = 1 } },
          "challenge01-b" = { hostname = "b.challenge01.potluckctf.local", ip = "10.0.1.11", type = "e2-standard-2", labels = { challenge = 1 } },
        }
      },
      "challenge02" = {
        subnet = "10.0.2.0/24",
        servers = {
          "challenge02-a" = { hostname = "a.challenge02.potluckctf.local", ip = "10.0.2.10", type = "e2-standard-2", labels = { challenge = 1 } },
          "challenge02-b" = { hostname = "b.challenge02.potluckctf.local", ip = "10.0.2.11", type = "e2-standard-2", labels = { challenge = 1 } },
        }
      }
    }
    monitor = {
      "monitor-a" = { hostname = "monitor.potluckctf.local", ip = "10.0.0.100", type = "e2-standard-8", labels = { monitor = 1 } },
    }
  }
  challenge_servers = merge([for challenge_name, challenge in local.server_settings.challenges : { for server_name, server in challenge.servers : server_name => merge(server, { challenge_id : challenge_name }) }]...)

  sshkeys = ["ZetaTwo2018"]
}

resource "google_compute_instance_group" "challenge_group" {
  provider    = google-beta
  for_each    = local.server_settings.challenges
  name        = "${each.key}-group"
  description = "${each.key} server group"

  instances = [for server_name, server in each.value.servers : google_compute_instance.challenge_server[server_name].self_link]

  named_port {
    name = "challenge"
    port = "31337"
  }
}

resource "google_compute_instance" "challenge_server" {
  provider     = google-beta
  for_each     = local.challenge_servers
  name         = each.key
  machine_type = each.value.type

  tags = ["potluckctf", "challenge", each.value.challenge_id]
  labels = {
    challenge = 1
  }

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 16
    }
  }

  network_interface {
    # A default network is created for all GCP projects
    subnetwork = google_compute_subnetwork.potluckctf_challenge_subnet[each.value.challenge_id].id
    network    = google_compute_network.potluckctf_network.id
    access_config {
      // Ephemeral public IP
    }
  }
}

resource "google_compute_instance" "scoreboard_server" {
  provider     = google-beta
  for_each     = local.server_settings.scoreboard
  name         = each.key
  machine_type = each.value.type
  zone         = "europe-west3-b"

  tags = ["potluckctf", "scoreboard"]
  labels = {
    scoreboard = 1
  }

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 32
    }
  }

  network_interface {
    network    = google_compute_network.potluckctf_network.id
    subnetwork = google_compute_subnetwork.potluckctf_subnet.id
    network_ip = each.value.ip
    access_config {
      // Ephemeral public IP
    }
  }
}

resource "google_compute_instance" "monitor_server" {
  provider     = google-beta
  for_each     = local.server_settings.monitor
  name         = each.key
  machine_type = each.value.type
  zone         = "europe-west3-b"

  tags = ["potluckctf", "monitor"]
  labels = {
    monitor = 1
  }

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 128
    }
  }

  network_interface {
    network    = google_compute_network.potluckctf_network.id
    network_ip = each.value.ip
    subnetwork = google_compute_subnetwork.potluckctf_subnet.id
    access_config {
      // Ephemeral public IP
    }
  }
}

# VPC
resource "google_compute_network" "potluckctf_network" {
  name                    = "potluckctf-network"
  provider                = google-beta
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "potlucktf_firewall_ssh" {
  name     = "potluckctf-fw-ssh"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name

  source_ranges = ["35.235.240.0/20"] # IAP IP range

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "potlucktf_firewall_healthcheck" {
  name     = "potluckctf-fw-healthcheck"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"] # GFE IP range
  target_tags   = ["challenge"]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
}

resource "google_compute_firewall" "potlucktf_firewall_challenge" {
  name     = "potluckctf-fw-challenge"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"] # GFE IP range
  target_tags   = ["challenge"]

  allow {
    protocol = "tcp"
    ports    = ["31337"]
  }
}

resource "google_compute_firewall" "potlucktf_firewall_syslog" {
  name     = "potluckctf-fw-syslog"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name

  source_ranges = ["10.0.0.0/8"] # Internal IP range
  target_tags   = ["monitor"]

  allow {
    protocol = "tcp"
    ports    = ["514"]
  }
}

resource "google_compute_subnetwork" "potluckctf_subnet" {
  name          = "potluckctf-subnet"
  provider      = google-beta
  ip_cidr_range = "10.0.0.0/24"
  network       = google_compute_network.potluckctf_network.id
}


# backend subnet
resource "google_compute_subnetwork" "potluckctf_challenge_subnet" {
  for_each      = local.server_settings.challenges
  name          = "potluckctf-${each.key}-subnet"
  provider      = google-beta
  ip_cidr_range = each.value.subnet
  network       = google_compute_network.potluckctf_network.id
}

# reserved IP address
resource "google_compute_global_address" "challenge_ip" {
  for_each = local.server_settings.challenges
  provider = google-beta
  name     = "${each.key}-ip"
}

# forwarding rule
resource "google_compute_global_forwarding_rule" "challenge_forwarding" {
  for_each              = local.server_settings.challenges
  name                  = "${each.key}-forwarding-rule"
  provider              = google-beta
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "31337"
  target                = google_compute_target_tcp_proxy.challenge_proxy[each.key].id
  ip_address            = google_compute_global_address.challenge_ip[each.key].id
}

resource "google_compute_target_tcp_proxy" "challenge_proxy" {
  for_each        = local.server_settings.challenges
  provider        = google-beta
  name            = "${each.key}-health-check"
  backend_service = google_compute_backend_service.challenge_service[each.key].id
}

# backend service
resource "google_compute_backend_service" "challenge_service" {
  for_each = local.server_settings.challenges

  provider              = google-beta
  name                  = "${each.key}-backend-service"
  protocol              = "TCP"
  port_name             = "challenge"
  load_balancing_scheme = "EXTERNAL"
  timeout_sec           = 10
  health_checks         = [google_compute_health_check.challenge_healthcheck[each.key].id]
  session_affinity      = "CLIENT_IP"
  backend {
    group           = google_compute_instance_group.challenge_group[each.key].id
    balancing_mode  = "UTILIZATION"
    max_utilization = 1.0
    capacity_scaler = 1.0
  }
}

resource "google_compute_health_check" "challenge_healthcheck" {
  for_each           = local.server_settings.challenges
  provider           = google-beta
  name               = "${each.key}-health-check"
  timeout_sec        = 1
  check_interval_sec = 1

  tcp_health_check {
    port = "80"
  }
}


#
#resource "hcloud_floating_ip_assignment" "web-ip-assignment" {
#  floating_ip_id = "[REDACTED]" # TODO (P0): Add new static ip
#  server_id      = hcloud_server.livectf-web["web1.livectf.local"].id
#}


# generate inventory file for Ansible
resource "local_file" "hosts_ansible_inventory" {
  content = templatefile("${path.module}/hosts.tpl",
    {
      potluckctf-scoreboard = google_compute_instance.scoreboard_server
      potluckctf-challenges = google_compute_instance.challenge_server
      potluckctf-monitor    = google_compute_instance.monitor_server
      potluckctf-all        = merge(google_compute_instance.scoreboard_server, google_compute_instance.challenge_server, google_compute_instance.monitor_server)

      server_settings = merge(local.server_settings.scoreboard, local.challenge_servers, local.server_settings.monitor)
    }
  )
  filename        = "hosts.yml"
  file_permission = "0644"
}

## generate SSH config file
#resource "local_file" "hosts_ssh_config" {
#  content = templatefile("${path.module}/hosts.ssh.tpl",
#    {
#      livectf-web             = hcloud_server.livectf-web
#      livectf-builder         = hcloud_server.livectf-builder
#      livectf-builder-volumes = hcloud_volume.livectf-builder
#      livectf-runner          = hcloud_server.livectf-runner
#      livectf-runner-volumes  = hcloud_volume.livectf-runner
#      livectf-monitor         = hcloud_server.livectf-monitor
#      livectf-all             = merge(hcloud_server.livectf-web, hcloud_server.livectf-builder, hcloud_server.livectf-runner, hcloud_server.livectf-monitor)
#
#      server_settings = merge(local.server_settings.web, local.server_settings.builders, local.server_settings.runners, local.server_settings.monitor)
#      subnet          = hcloud_network_subnet.network-subnet
#    }
#  )
#  filename        = "hosts.ssh.conf"
#  file_permission = "0644"
#}
