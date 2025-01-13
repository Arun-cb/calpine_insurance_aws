from django.apps import AppConfig
# from base.api import access_sharepoint


class BaseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'base'
