all:
  hosts:
  children:
    scoreboard:
      hosts:
%{ for server in potluckctf-scoreboard ~}
        ${server.name}:
%{ endfor ~}
    challenges:
      children:
%{ for challenge_name, challenge in potluckctf-challenges ~}
        ${challenge_name}:
          hosts:
%{ for server_name, server in challenge.servers ~}
            ${server_name}:
%{ endfor ~}
%{ endfor ~}

    docker:
      hosts:
%{ for name, server in {for name, server in server_settings: name => server if contains(keys(server.labels), "docker")} ~}
        ${name}:
%{ endfor ~}

    docker_single:
      hosts:
%{ for name, server in {for name, server in server_settings: name => server if contains(keys(server.labels), "docker_single")} ~}
        ${name}:
%{ endfor ~}

    monitor:
      hosts:
%{ for server in [for s in potluckctf-all: s if contains(s.tags, "monitor")] ~}
        ${server.name}:
%{ endfor ~}
