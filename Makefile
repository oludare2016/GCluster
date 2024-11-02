# Makefile for basic Django commands

# Ensure you have the environment set up correctly
ENV_SETTINGS=DJANGO_SETTINGS_MODULE=global_cluster_backend.settings.base

# Run migrations
migrate:
	$(ENV_SETTINGS) python manage.py migrate --noinput

# Make migrations
makemigrations:
	$(ENV_SETTINGS) python manage.py makemigrations

# Create a superuser
createsuperuser:
	$(ENV_SETTINGS) python manage.py createsuperuser

# Run the development server
runserver:
	$(ENV_SETTINGS) python manage.py runserver

# Collect static files
collectstatic:
	$(ENV_SETTINGS) python manage.py collectstatic --noinput

# Run tests
test:
	$(ENV_SETTINGS) python manage.py test

# Load initial data
loaddata:
	$(ENV_SETTINGS) python manage.py loaddata initial_data.json

# Clear database and run migrations again
resetdb:
	$(ENV_SETTINGS) python manage.py flush --noinput
	$(ENV_SETTINGS) python manage.py migrate --noinput
	$(ENV_SETTINGS) python manage.py loaddata initial_data.json

# Update API schema
apidoc:
	$(ENV_SETTINGS) python manage.py spectacular --color --file api_schema.yml

load-initial-users:
	$(ENV_SETTINGS) python manage.py loaddata useraccounts/fixtures/initial_users.json
