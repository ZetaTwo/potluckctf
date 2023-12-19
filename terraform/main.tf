provider "google-beta" {
  project = "potluck-ctf"
  region  = "europe-west3"
  zone    = "europe-west3-b"
}

terraform {
  required_version = ">= 1.4.4"
}

resource "google_dns_managed_zone" "play" {
  name     = "play-zone"
  provider = google-beta
  dns_name = "play.potluckctf.com."
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

resource "google_compute_subnetwork" "potluckctf_subnet" {
  name          = "potluckctf-subnet"
  provider      = google-beta
  ip_cidr_range = "10.0.0.0/24"
  network       = google_compute_network.potluckctf_network.id
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
