# TODO: import challenge delivery SA + bucket into Terraform
#resource "google_service_account" "challenge_delivery_service_account" {
#  provider     = google-beta
#  for_each     = local.delivery_challenges ? local.server_settings.challenges : {}
#  account_id   = "${each.key}-author"
#  display_name = "${each.key} Challenge Delivery"
#}
