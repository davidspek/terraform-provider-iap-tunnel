ephemeral "google-iap_tunnel" "example" {
  project     = "my-project"
  zone        = "us-central1-a"
  instance    = "my-target"
  remote_port = 8080
  interface   = "nic0"
  local_port  = 8080

}
