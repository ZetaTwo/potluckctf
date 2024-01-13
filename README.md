# 37C3 Potluck CTF

This repository contains all the challenges and infrastructure resources for the 37C3 Potluck CTF. You can read more about the event on the [website](https://potluckctf.com) and checkout the [scoreboard archive](https://2023.potluckctf.com) for the end results and an overview of the challenges.

* [ansible](ansible/) - Ansible playbook to set up all the servers used in the infrastructure.
* [challenge-delivery](challenge-delivery/) - notes and scripts used for the challenge registration and delivery process.
* [challenge-deployment](challenge-deployment/) - Makefiles, metadata and other resources for the challenges used to deploy them.
* [challenges](challenges/) - The challenges used in the competition. The README file contains a table of challenges and their respective authors.
* [grafana](grafana/) - An export of the simple Grafana dashboard used to monitor the infrastructure
* [hacks](hacks/) - Various small ad-hoc scripts used during the operations and deployment of the CTF.
* [scoreboard](scoreboard/) - The end results of the event, including the full score and the filtered version uploaded to CTFTime.
* [scripts](scripts/) - Scripts used during the operations and deployment of the CTF.
* [terraform](terraform/) - The terraform plans used to deploy the infrastructure for the CTF.

## Author

Everything except the [challenges](challenges/) is created by ZetaTwo <calle.svensson@zeta-two.com>. The [challenges](challenges/) are created by their respective authors listed in the [README file](challenges/README.md).

## License

With a few small excpetions in one of the challenges, everything is licensed under an Aapache 2.0 license.
If you find anything here useful and end up using it for anything else it would be cool to hear about it.
