# TODO: customize port
# TODO: enable nested virt for chall 1+25 (advanced_machine_features / enable_nested_virtualization)

locals {
  open_scoreboard      = true
  ctf_started          = false
  artifacts_challenges = true
  deploy_challenges    = false

  server_settings = {
    scoreboard = {
      "scoreboard-a" = { ip = "10.0.0.10", type = "e2-standard-8", labels = { bastion = 1 } },
    }
    challenges = {
      "challenge00" = {
        subnet            = "10.0.137.0/24",
        servers = {
          "challenge00-a" = { ip = "10.0.137.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
          #"challenge00-b" = { ip = "10.0.137.11", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge01" = {
        subnet            = "10.0.1.0/24",
        servers = {
          "challenge01-a" = { ip = "10.0.1.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge02" = {
        subnet            = "10.0.2.0/24",
        servers = {
          "challenge02-a" = { ip = "10.0.2.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },

      "challenge03" = {
        subnet            = "10.0.3.0/24",
        servers = {
          "challenge03-a" = { ip = "10.0.3.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      #"challenge04" = {}, # No server
      "challenge05" = {
        subnet            = "10.0.5.0/24",
        servers = {
          "challenge05-a" = { ip = "10.0.5.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge06" = {
        subnet            = "10.0.6.0/24",
        servers = {
          "challenge06-a" = { ip = "10.0.6.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge07" = {
        subnet            = "10.0.7.0/24",
        servers = {
          "challenge07-a" = { ip = "10.0.7.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      #"challenge08" = {}, # TODO: Special setup
      "challenge09" = {
        subnet            = "10.0.9.0/24",
        servers = {
          "challenge09-a" = { ip = "10.0.9.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      #"challenge10" = {}, # TODO: Special setup
      "challenge11" = {
        subnet            = "10.0.11.0/24",
        servers = {
          "challenge11-a" = { ip = "10.0.11.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
        }
      },
      "challenge12" = {
        subnet            = "10.0.12.0/24",
        servers = {
          "challenge12-a" = { ip = "10.0.12.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge13" = {
        subnet            = "10.0.13.0/24",
        servers = {
          "challenge13-a" = { ip = "10.0.13.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      #"challenge14" = {}, # No server
      "challenge15" = {
        subnet            = "10.0.15.0/24",
        servers = {
          "challenge15-a" = { ip = "10.0.15.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      #"challenge16" = {}, # No server
      #"challenge17" = {}, # TODO: Special setup
      "challenge18" = {
        subnet            = "10.0.18.0/24",
        servers = {
          "challenge18-a" = { ip = "10.0.18.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge19" = {
        subnet            = "10.0.19.0/24",
        servers = {
          "challenge19-a" = { ip = "10.0.19.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge21" = {
        subnet            = "10.0.21.0/24",
        servers = {
          "challenge20-a" = { ip = "10.0.21.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge22" = {
        subnet            = "10.0.22.0/24",
        servers = {
          "challenge22-a" = { ip = "10.0.22.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      #"challenge23" = {}, # Same server as challenge-22
      "challenge24" = {
        subnet            = "10.0.24.0/24",
        servers = {
          "challenge24-a" = { ip = "10.0.24.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge25" = {
        subnet            = "10.0.25.0/24",
        servers = {
          "challenge25-a" = { ip = "10.0.25.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge26" = {
        subnet            = "10.0.26.0/24",
        servers = {
          "challenge26-a" = { ip = "10.0.26.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge27" = {
        subnet            = "10.0.27.0/24",
        servers = {
          "challenge27-a" = { ip = "10.0.27.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge28" = {
        subnet            = "10.0.28.0/24",
        servers = {
          "challenge28-a" = { ip = "10.0.28.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
      "challenge29" = {
        subnet            = "10.0.29.0/24",
        servers = {
          "challenge29-a" = { ip = "10.0.29.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1, docker_single: 1 } },
        }
      },
    }
    monitor = {
      "monitor-a" = { ip = "10.0.0.100", type = "e2-standard-8", labels = { monitor = 1 } },
    }
  }
  challenge_servers = merge([for challenge_name, challenge in local.server_settings.challenges : { for server_name, server in challenge.servers : server_name => merge(server, { challenge_id : challenge_name }) }]...)
}
