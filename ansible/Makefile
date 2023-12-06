deploy:
	ansible-playbook -i ../terraform/hosts.yml potluckctf-playbook.yml

inventory:
	ansible-inventory -i ../terraform/hosts.yml --list

.PHONY: deploy inventory
