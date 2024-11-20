from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from datetime import timedelta
from .models import Task, User
from django.conf import settings

@shared_task
def send_due_date_emails():
    print('inside tasks.py')
    tomorrow = timezone.now().date() + timedelta(days=1)
    print(tomorrow)
    tasks_due_tomorrow = Task.objects.filter(due_date=tomorrow)
    print(tasks_due_tomorrow)
    if tasks_due_tomorrow:
        for task in tasks_due_tomorrow:
            username = task.assigned_to
            if username:
                try:
                    user = User.objects.get(username=username)
                    user_email = user.email
                    email_subject = f"Reminder: Task '{task.title}' is Due Tomorrow"
                    email_body = render_to_string('emailTemplate.html', {'task': task})
                    print('assigned user email is: ', user_email)
                    send_mail(
                        subject=email_subject,
                        message=f"Hello, \n\nThis is a reminder that the task '{task.title}' is due tomorrow. Please ensure you complete it on time.\n\nThank you.",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user_email], 
                        html_message=email_body
                    )
                except User.DoesNotExist:
                    print(f"User with username {username} does not exist.")


    