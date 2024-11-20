from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Task, Notifications, User


@receiver(post_save, sender=Task)
def handleTaskNotifications(sender, instance, created, **kwargs):
    user = User.objects.get(username=instance.assigned_to)
    if created:
        print('in creation of new task')
        message = f"A new task '{instance.title}' has been assigned to you."
        Notifications.objects.create(user=user, message=message)
    else:
        print('in status marked as completed')
        if instance.status == 'completed':
            message = f"Task '{instance.title}' has been marked as completed."
            Notifications.objects.create(user=user, message=message)
        else:
            changes = []
            for field in instance._meta.get_fields():
                if not field.concrete or field.is_relation:
                    continue

                field_name = field.name
                old_value = getattr(instance, f'_{field_name}_old', None)
                new_value = getattr(instance, field_name)

                if old_value != new_value:
                    changes.append(field_name)
                    setattr(instance, f'_{field_name}_old', new_value)

            if changes:
                message = f"Task '{instance.title}' has been updated."
                Notifications.objects.create(user=user, message=message)