#!/bin/sh
docker compose exec web pipenv run python manage.py shell -c 'from django.core.cache import cache; cache.clear()'
