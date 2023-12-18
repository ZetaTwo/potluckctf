all:
  hosts:
  children:
    scoreboard:
      hosts:
%{ for server in potluckctf-scoreboard ~}
        ${server.name}:
%{ endfor ~}
    challenges:
      hosts:
%{ for server in potluckctf-challenges ~}
        ${server.name}:
%{ endfor ~}

    docker:
      hosts:
%{ for name, server in {for name, server in server_settings: name => server if contains(keys(server.labels), "docker")} ~}
        ${name}:
%{ endfor ~}

    monitor:
      hosts:
%{ for server in [for s in potluckctf-all: s if contains(s.tags, "monitor")] ~}
        ${server.name}:
%{ endfor ~}
