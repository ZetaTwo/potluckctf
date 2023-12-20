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

# generate inventory file for Ansible
resource "local_file" "hosts_ansible_inventory" {
  content = templatefile("${path.module}/hosts.tpl",
    {
      potluckctf-scoreboard = google_compute_instance.scoreboard_server
      potluckctf-challenges = local.deploy_challenges ? google_compute_instance.challenge_server : {}
      potluckctf-monitor    = google_compute_instance.monitor_server
      potluckctf-all        = merge(google_compute_instance.scoreboard_server, local.deploy_challenges ? google_compute_instance.challenge_server : {}, google_compute_instance.monitor_server)

      server_settings = merge(local.server_settings.scoreboard, local.deploy_challenges ? local.challenge_servers : {}, local.server_settings.monitor)
    }
  )
  filename        = "hosts.yml"
  file_permission = "0644"
}
