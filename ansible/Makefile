deploy:
	ansible-playbook -i ../terraform/hosts.yml potluckctf-playbook.yml

dev:
	ansible-playbook -i ../terraform/hosts.yml dev-playbook.yml

inventory:
	ansible-inventory -i ../terraform/hosts.yml --list

dependencies:
	$$(gcloud info --format="value(basic.python_location)") -m pip install numpy

registry:
	docker run --rm -d -p 127.0.0.1:5001:5000 -p 172.17.0.1:5001:5000 --name registry registry:2

cleanup:
	docker stop registry

.PHONY: deploy dev inventory dependencies registry cleanup inventory
