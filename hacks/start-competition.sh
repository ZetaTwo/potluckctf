#!/bin/sh
sudo docker compose exec web pipenv run python manage.py shell -c 'from core.models import *; print(" ".join(str(i) for i in Challenge.objects.values_list("id", flat=True)))'
sudo docker compose exec web pipenv run python manage.py startctf 9 10 11 14 15 16 1 5 4 7 8 12 13 20 22 23 24 25 26 3 28 27 21 2 17 18 19 6 29
