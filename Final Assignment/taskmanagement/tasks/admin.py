from django.contrib import admin
from .models import Task, Tag, Comment, User, DueDateExtensionRequest, Subtask, Notifications
# Register your models here.

admin.site.register(User)
admin.site.register(Task)
admin.site.register(Subtask)
admin.site.register(Comment)
admin.site.register(Tag)
admin.site.register(DueDateExtensionRequest)
admin.site.register(Notifications)