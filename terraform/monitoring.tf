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

resource "google_compute_firewall" "potlucktf_firewall_node_exporter" {
  name     = "potluckctf-fw-node-exporter"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name

  source_ranges = ["10.0.0.0/8"] # Internal IP range

  allow {
    protocol = "tcp"
    ports    = ["9100"]
  }
}
