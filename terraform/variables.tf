locals {
  open_scoreboard      = true
  ctf_started          = false
  delivery_challenges  = true
  artifacts_challenges = true
  deploy_challenges    = true

  server_settings = {
    scoreboard = {
      "scoreboard-a" = { ip = "10.0.0.10", type = "e2-standard-8", labels = { bastion = 1 } },
    }
    challenges = {
      "challenge00" = {
        author_sa = "user:calle.svensson@zeta-two.com",
        subnet = "10.0.137.0/24",
        servers = {
          "challenge00-a" = { ip = "10.0.137.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
          #"challenge00-b" = { ip = "10.0.137.11", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge01" = {
        author_sa = "serviceAccount:challenge-author-1@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.1.0/24",
        servers = {
          "challenge01-a" = { ip = "10.0.1.10", type = "n2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1, nested_virtualization = 1 } },
        }
      },
      "challenge03" = {
        author_sa = "serviceAccount:challenge-author-3@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.3.0/24",
        servers = {
          "challenge03-a" = { ip = "10.0.3.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      #"challenge04" = {}, # No server
      "challenge05" = {
        author_sa = "serviceAccount:challenge-author-5@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.5.0/24",
        servers = {
          "challenge05-a" = { ip = "10.0.5.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge06" = {
        author_sa = "serviceAccount:challenge-author-6@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.6.0/24",
        servers = {
          "challenge06-a" = { ip = "10.0.6.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge07" = {
        author_sa = "serviceAccount:challenge-author-7@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.7.0/24",
        servers = {
          "challenge07-a" = { ip = "10.0.7.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      #"challenge08" = {}, # Special setup
      "challenge09" = {
        author_sa = "serviceAccount:challenge-author-9@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.9.0/24",
        servers = {
          "challenge09-a" = { ip = "10.0.9.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      #"challenge10" = {}, # Special setup
      "challenge11" = {
        author_sa = "serviceAccount:challenge-author-11@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.11.0/24",
        servers = {
          "challenge11-a" = { ip = "10.0.11.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1 } },
        }
      },
      "challenge12" = {
        author_sa = "serviceAccount:challenge-author-12@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.12.0/24",
        servers = {
          "challenge12-a" = { ip = "10.0.12.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge13" = {
        author_sa = "serviceAccount:challenge-author-13@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.13.0/24",
        servers = {
          "challenge13-a" = { ip = "10.0.13.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      #"challenge14" = {}, # No server
      "challenge15" = {
        author_sa = "serviceAccount:challenge-author-15@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.15.0/24",
        servers = {
          "challenge15-a" = { ip = "10.0.15.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      #"challenge16" = {}, # No server
      "challenge17" = {
        author_sa = "serviceAccount:challenge-author-17@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.17.0/24",
        servers = {
          "challenge17-a" = { ip = "10.0.17.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge18" = {
        author_sa = "serviceAccount:challenge-author-18@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.18.0/24",
        servers = {
          "challenge18-a" = { ip = "10.0.18.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge19" = {
        author_sa = "serviceAccount:challenge-author-19@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.19.0/24",
        servers = {
          "challenge19-a" = { ip = "10.0.19.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge21" = {
        author_sa = "serviceAccount:challenge-author-21@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.21.0/24",
        servers = {
          "challenge21-a" = { ip = "10.0.21.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge22" = {
        author_sa = "serviceAccount:challenge-author-22@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.22.0/24",
        servers = {
          "challenge22-a" = { ip = "10.0.22.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      #"challenge23" = {}, # Same server as challenge-22
      "challenge24" = {
        author_sa = "serviceAccount:challenge-author-24@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.24.0/24",
        servers = {
          "challenge24-a" = { ip = "10.0.24.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge25" = {
        author_sa = "serviceAccount:challenge-author-25@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.25.0/24",
        servers = {
          "challenge25-a" = { ip = "10.0.25.10", type = "n2-standard-8", labels = { challenge = 1, nested_virtualization = 1 } },
        }
      },
      "challenge26" = {
        author_sa = "serviceAccount:challenge-author-26@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.26.0/24",
        servers = {
          "challenge26-a" = { ip = "10.0.26.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge27" = {
        author_sa = "serviceAccount:challenge-author-27@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.27.0/24",
        servers = {
          "challenge27-a" = { ip = "10.0.27.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge28" = {
        author_sa = "serviceAccount:challenge-author-28@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.28.0/24",
        servers = {
          "challenge28-a" = { ip = "10.0.28.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
      "challenge29" = {
        author_sa = "serviceAccount:challenge-author-29@potluck-ctf.iam.gserviceaccount.com",
        subnet = "10.0.29.0/24",
        servers = {
          "challenge29-a" = { ip = "10.0.29.10", type = "e2-standard-8", labels = { challenge = 1, docker = 1, docker_single = 1 } },
        }
      },
    }
    monitor = {
      "monitor-a" = { ip = "10.0.0.100", type = "e2-standard-8", labels = { monitor = 1 } },
    }
  }
  challenge_servers = merge([for challenge_name, challenge in local.server_settings.challenges : { for server_name, server in challenge.servers : server_name => merge(server, { challenge_id : challenge_name }) }]...)
}
