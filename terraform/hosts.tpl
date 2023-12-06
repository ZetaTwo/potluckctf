all:
  vars:
    ansible_user: root
    ansible_ssh_extra_args: '-R 5001:localhost:5001'
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

    monitor:
      hosts:
%{ for server in [for s in potluckctf-all: s if contains(s.tags, "monitor")] ~}
        ${server.name}:
%{ endfor ~}
