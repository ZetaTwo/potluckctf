deploy:
	ansible-playbook -i ../terraform/hosts.yml potluckctf-playbook.yml

dev:
	ansible-playbook -i ../terraform/hosts.yml dev-playbook.yml

inventory:
	ansible-inventory -i ../terraform/hosts.yml --list

dependencies:
	$$(gcloud info --format="value(basic.python_location)") -m pip install numpy

.PHONY: deploy dev inventory dependencies
