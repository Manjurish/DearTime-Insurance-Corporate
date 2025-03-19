from django.apps import AppConfig
import os

class PortalConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Portal'

    def ready(self):
        from MessageQueue import sender

        run_once = os.environ.get('CMDLINERUNNER_RUN_ONCE')
        if run_once is not None:
            return
        else:
            os.environ['CMDLINERUNNER_RUN_ONCE'] = 'True'
            sender.start()