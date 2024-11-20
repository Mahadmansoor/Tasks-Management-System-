from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'taskmanagement.settings')

app = Celery('taskmanagement')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related config keys should have a `CELERY_` prefix.
app.conf.enable_utc = False
app.conf.update(timezone = 'Asia/Karachi')


app.conf.beat_schedule = {
    'scheduled_send_email': {
        'task': 'tasks.tasks.send_due_date_emails',
        'schedule': crontab(hour=10, minute=51), #(the time is set for testing, Actually it would be hour=0, minute=0 to send email one day before due date)
    },
}


app.config_from_object('django.conf:settings', namespace='CELERY')



app.autodiscover_tasks()

