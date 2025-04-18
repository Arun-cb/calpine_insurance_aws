from django.apps import AppConfig
from django.utils.module_loading import import_module


class BaseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'base'

    def ready(self):
        import_module('base.signals')
