
resource "google_compute_instance_group" "challenge_group" {
  provider    = google-beta
  for_each    = local.deploy_challenges ? local.server_settings.challenges : {}
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
  for_each     = local.deploy_challenges ? local.server_settings.challenges : {}
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


resource "google_compute_firewall" "potlucktf_firewall_healthcheck" {
  name     = "potluckctf-fw-healthcheck"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name
  count    = local.deploy_challenges ? 1 : 0

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
  count    = (local.ctf_started && local.deploy_challenges) ? 1 : 0

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"] # GFE IP range
  target_tags   = ["challenge"]

  allow {
    protocol = "tcp"
    ports    = ["31337"]
  }
}

resource "google_compute_firewall" "potlucktf_firewall_challenge_iap" {
  name     = "potluckctf-fw-challenge-iap"
  provider = google-beta
  network  = google_compute_network.potluckctf_network.name
  count    = local.deploy_challenges ? 1 : 0

  source_ranges = ["35.235.240.0/20"] # IAP IP range

  allow {
    protocol = "tcp"
    ports    = ["31337"]
  }
}


# backend subnet
resource "google_compute_subnetwork" "potluckctf_challenge_subnet" {
  for_each      = local.deploy_challenges ? local.server_settings.challenges : {}
  name          = "potluckctf-${each.key}-subnet"
  provider      = google-beta
  ip_cidr_range = each.value.subnet
  network       = google_compute_network.potluckctf_network.id
}

# reserved IP address
resource "google_compute_global_address" "challenge_ip" {
  for_each = local.deploy_challenges ? local.server_settings.challenges : {}
  provider = google-beta
  name     = "${each.key}-ip"
}

# forwarding rule
resource "google_compute_global_forwarding_rule" "challenge_forwarding" {
  for_each              = local.deploy_challenges ? local.server_settings.challenges : {}
  name                  = "${each.key}-forwarding-rule"
  provider              = google-beta
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "31337"
  target                = google_compute_target_tcp_proxy.challenge_proxy[each.key].id
  ip_address            = google_compute_global_address.challenge_ip[each.key].id
}

resource "google_compute_target_tcp_proxy" "challenge_proxy" {
  for_each        = local.deploy_challenges ? local.server_settings.challenges : {}
  provider        = google-beta
  name            = "${each.key}-health-check"
  backend_service = google_compute_backend_service.challenge_service[each.key].id
}

resource "google_dns_record_set" "challenge_subdomain" {
  for_each = local.deploy_challenges ? local.server_settings.challenges : {}
  provider = google-beta
  name     = "${each.key}.${google_dns_managed_zone.play.dns_name}"
  type     = "A"
  ttl      = 300

  managed_zone = google_dns_managed_zone.play.name

  rrdatas = [google_compute_global_address.challenge_ip[each.key].address]
}

# backend service
resource "google_compute_backend_service" "challenge_service" {
  for_each = local.deploy_challenges ? local.server_settings.challenges : {}

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
  for_each           = local.deploy_challenges ? local.server_settings.challenges : {}
  provider           = google-beta
  name               = "${each.key}-health-check"
  timeout_sec        = 1
  check_interval_sec = 1

  tcp_health_check {
    port = "80"
  }
}
