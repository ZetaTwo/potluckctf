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
%{ for server in [for s in potluckctf-all: s if contains(keys(s.labels), "docker")] ~}
        ${server.name}:
%{ endfor ~}

    monitor:
      hosts:
%{ for server in [for s in potluckctf-all: s if contains(s.tags, "monitor")] ~}
        ${server.name}:
%{ endfor ~}
