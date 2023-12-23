
resource "google_dns_record_set" "challenge_subdomain_challenge10" {
  provider = google-beta
  name     = "challenge10.${google_dns_managed_zone.play.dns_name}"
  type     = "NS"
  ttl      = 300

  managed_zone = google_dns_managed_zone.play.name

  rrdatas = [
    "ns-cloud-d1.googledomains.com.",
    "ns-cloud-d2.googledomains.com.",
    "ns-cloud-d3.googledomains.com.",
    "ns-cloud-d4.googledomains.com.",
  ]
}
