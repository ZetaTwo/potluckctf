
locals {
  ctf_started = false

  server_settings = {
    scoreboard = {
      "scoreboard-a" = { hostname = "scoreboard.livectf.local", ip = "10.0.0.10", type = "e2-standard-8", labels = { bastion = 1 } },
    }
    challenges = {
      "challenge01" = {
        subnet = "10.0.1.0/24",
        servers = {
          "challenge01-a" = { hostname = "a.challenge01.potluckctf.local", ip = "10.0.1.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
          "challenge01-b" = { hostname = "b.challenge01.potluckctf.local", ip = "10.0.1.11", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
        }
      },
      "challenge02" = {
        subnet = "10.0.2.0/24",
        servers = {
          "challenge02-a" = { hostname = "a.challenge02.potluckctf.local", ip = "10.0.2.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
          "challenge02-b" = { hostname = "b.challenge02.potluckctf.local", ip = "10.0.2.11", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
        }
      },
      
#      "challenge03" = {
#        subnet = "10.0.3.0/24",
#        servers = {
#          "challenge03-a" = { hostname = "a.challenge03.potluckctf.local", ip = "10.0.3.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge04" = {}, # No server
#      "challenge05" = {
#        subnet = "10.0.5.0/24",
#        servers = {
#          "challenge05-a" = { hostname = "a.challenge05.potluckctf.local", ip = "10.0.5.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge06" = {}, # No server
#      "challenge07" = {
#        subnet = "10.0.7.0/24",
#        servers = {
#          "challenge07-a" = { hostname = "a.challenge07.potluckctf.local", ip = "10.0.7.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge08" = {}, # TODO: Special setup
#      "challenge09" = {
#        subnet = "10.0.9.0/24",
#        servers = {
#          "challenge09-a" = { hostname = "a.challenge09.potluckctf.local", ip = "10.0.9.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge10" = {}, # TODO: Special setup
#      "challenge11" = {
#        subnet = "10.0.11.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge11.potluckctf.local", ip = "10.0.11.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge12" = {
#        subnet = "10.0.12.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge12.potluckctf.local", ip = "10.0.12.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge13" = {
#        subnet = "10.0.13.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge13.potluckctf.local", ip = "10.0.13.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge14" = {
#        subnet = "10.0.14.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge14.potluckctf.local", ip = "10.0.14.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge15" = {
#        subnet = "10.0.15.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge15.potluckctf.local", ip = "10.0.15.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge16" = {}, # No server
#      #"challenge17" = {}, # TODO: Special setup
#      "challenge18" = {
#        subnet = "10.0.18.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge18.potluckctf.local", ip = "10.0.18.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge19" = {
#        subnet = "10.0.19.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge19.potluckctf.local", ip = "10.0.19.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge20" = {}, # No server
#      "challenge21" = {
#        subnet = "10.0.21.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge21.potluckctf.local", ip = "10.0.21.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge22" = {
#        subnet = "10.0.22.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge22.potluckctf.local", ip = "10.0.22.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      #"challenge23" = {}, # Same server as challenge-22
#      "challenge24" = {
#        subnet = "10.0.24.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge24.potluckctf.local", ip = "10.0.24.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge25" = {
#        subnet = "10.0.25.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge25.potluckctf.local", ip = "10.0.25.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge26" = {
#        subnet = "10.0.26.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge26.potluckctf.local", ip = "10.0.26.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge27" = {
#        subnet = "10.0.27.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge27.potluckctf.local", ip = "10.0.27.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
#      "challenge28" = {
#        subnet = "10.0.28.0/24",
#        servers = {
#          "challenge01-a" = { hostname = "a.challenge28.potluckctf.local", ip = "10.0.28.10", type = "e2-standard-2", labels = { challenge = 1, docker = 1 } },
#        }
#      },
    }
    monitor = {
      "monitor-a" = { hostname = "monitor.potluckctf.local", ip = "10.0.0.100", type = "e2-standard-8", labels = { monitor = 1 } },
    }
  }
  challenge_servers = merge([for challenge_name, challenge in local.server_settings.challenges : { for server_name, server in challenge.servers : server_name => merge(server, { challenge_id : challenge_name }) }]...)

  sshkeys = ["ZetaTwo2018"]
}