from django.urls import path, include
from . import views
urlpatterns = [
    path('register/', views.UserRegister, name='register'),
    path('login/', views.UserLogin, name='login'),
    path('logout/', views.Logout, name='logout'),
    path('create/', views.createTask,name='create'),
    path('readall/', views.readAllTasks,name='readall'),
    path('readone/<int:taskId>/', views.readOneTask,name='readone'),
    path('update/<int:taskId>/', views.updateTask,name='update'),
    path('delete/<int:taskId>/', views.deleteTask,name='delete'),
    path('priority/', views.priorityFilter, name='priorityFilter'),
    path('category/', views.categoryFilter, name='categoryFilter'),
    path('<int:taskId>/addcomment/', views.addComment, name='addcomment'),
    path('<int:taskId>/viewcomment/', views.viewComment, name='viewcomment'),
    path('<int:taskId>/createsubtask/', views.createSubtask, name='createsubtask'),
    path('<int:taskId>/viewsubtask/', views.viewSubtask, name='viewsubtask'),
    path('<int:taskId>/status/', views.trackStatus, name='trackstatus'),
    path('search/', views.search, name='search'),
    path('filter-by-tag/', views.tags, name='filter_tasks_by_tag'),
    path('<int:taskId>/request-extension/', views.duedateExtension, name='duedateextension'),
    path('dashboard/', views.dashboard, name='dashboard'),
]