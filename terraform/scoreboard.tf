
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

resource "google_compute_firewall" "potlucktf_firewall_scoreboard_http" {
  name     = "potluckctf-fw-scoreboard-http"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name
  count = local.open_scoreboard ? 1 : 0

  source_ranges = ["0.0.0.0/0"] # IAP IP range
  target_tags   = ["scoreboard"]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_dns_record_set" "scoreboard_subdomain" {
  provider = google-beta
  name     = google_dns_managed_zone.play.dns_name
  type     = "A"
  ttl      = 300

  managed_zone = google_dns_managed_zone.play.name

  rrdatas = [google_compute_instance.scoreboard_server["scoreboard-a"].network_interface[0].access_config[0].nat_ip]
}
