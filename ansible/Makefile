deploy:
	ansible-playbook -i ../terraform/hosts.yml potluckctf-playbook.yml

dev:
	ansible-playbook -i ../terraform/hosts.yml dev-playbook.yml

inventory:
	ansible-inventory -i ../terraform/hosts.yml --list

.PHONY: deploy dev inventory
