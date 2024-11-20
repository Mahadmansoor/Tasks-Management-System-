from ..core import error_codes
from django.contrib.auth import authenticate
from ..serializers import UserRegistrationSerializer, LoginSerializer, TaskSerializer, CommentSerializer, SubtaskSerializer, DueDateExtensionRequestSerializer
from ..models import User, Task, Tag, Comment, DueDateExtensionRequest, Subtask
from django.contrib.auth.hashers import make_password
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import logout

class RegLogin():
    def UserReg(self, data):
        try:
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')
            role = data.get('role')
            if role == 'admin' or role == 'user':
                hashed_password = make_password(password)
                if not User.objects.filter(Q(username=username)|Q(email=email)).exists():
                    user = User.objects.create(username=username,password=hashed_password,email=email,role=role)
                    user.save()
                    return {'ErrorCode': error_codes.SUCCESS, 'ErrorMSG': error_codes.USER_REGISTERED, 'data':UserRegistrationSerializer(user).data}
                else:
                    if User.objects.filter(username=username).exists():
                        return{'ErrorCode': error_codes.ERROR, 'ErrorMSG': error_codes.USER_ALREADY_REGISTERED_WITH_USERNAME}
                    elif User.objects.filter(email=email).exists():
                        return{'ErrorCode': error_codes.ERROR, 'ErrorMSG': error_codes.USER_ALREADY_REGISTERED_WITH_EMAIL}
            else:
                return{
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.INVALID_ROLE
                }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
    

    def UserLog(self, data, request):
        try:
            username = data['username']
            password = data['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                refresh = RefreshToken.for_user(user)
                token = {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    }
                request.session['refresh'] = token['refresh']
                request.session.save()
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'ErrorMSG': error_codes.USER_LOGGED_IN,
                    'data': {
                        'username': user.username,
                        'email': user.email,
                        'role': user.role
                    },
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.AUTHENTICATION_FAILED
                }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        

    def logout(self, request):
        try:
            refresh_token = request.session.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                logout(request)
                refresh_token = request.session.get("refresh")
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'SuccessMSG': error_codes.LOGOUT_MSG,
                }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.NO_REFRESH_TOKEN
                }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        

class CRUD():
    def create(self, request):
        try:
            serializer = TaskSerializer(data=request.data)
            if serializer.is_valid():
                data = serializer.validated_data
                data = {**serializer.validated_data, 'role': request.user.role}
                Title = data.get('title')
                Description = data.get('description')
                DueDate = data.get('due_date')
                Priority = data.get('priority')
                Category = data.get('category')
                Status = data.get('status')
                Role = data.get('role')
                assigned = data.get('assigned_to')
                if User.objects.filter(username=assigned).exists:
                    if Role == 'admin':
                        task = Task.objects.create(owner=request.user, title=Title, description=Description, due_date=DueDate, priority = Priority, category = Category, status= Status, assigned_to = assigned)
                        return{
                            'ErrorCode': error_codes.SUCCESS,
                            'SuccessMSG': error_codes.TASK_CREATED,
                            'TaskData': {
                                'id': task.id,
                                **TaskSerializer(task).data
                            }
                        }
                    else:
                        return{
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': error_codes.UNAUTHORIZED_TO_CREATE_TASK
                        }
                else:
                    return{
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.ASSIGNED_USER_DOES_NOT_EXIST
                    }
            else:
                return{
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': serializer.errors
                }
        except ObjectDoesNotExist:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.TASK_CREATION_FAILED
            }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }

    def readAll(self, request):
        try:
            if request.user.role == 'admin':
                tasks = Task.objects.all()
            else:
                if Task.objects.filter(assigned_to=request.user).exists():
                    tasks = Task.objects.filter(assigned_to=request.user)
                else:
                    return{
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.NO_TASK_ASSIGNED_TO_LOGGED_IN_USER
                    }
                serializer = TaskSerializer(tasks, many=True)
                return{
                    'ErrorCode': error_codes.SUCCESS,
                    'Tasks': serializer.data
                }
        except ObjectDoesNotExist:
            return {'ERROR MSG': error_codes.TASK_DOES_NOT_EXIST}
        


    def readOne(self, request, taskId):
        try:
            task = Task.objects.get(id=taskId)
            if task:
                if request.user.role == 'admin':
                    task = Task.objects.get(id=taskId)
                elif request.user.role == 'user' and task.assigned_to != str(request.user):
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.UNAUTHORIZED_TO_VIEW_TASK
                    }
                else:
                    task = Task.objects.get(id=taskId, assigned_to=request.user)
                    serializer = TaskSerializer(task)
                    return{
                        'ErrorCode': error_codes.SUCCESS,
                        'Task': serializer.data
                    }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
                }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }



    def update(self, request, task_id):
        try:
            task = Task.objects.get(id=task_id)
            if request.user.role == 'admin':
                with transaction.atomic():
                    task.save(user=request.user)
                print('user is admin')
                serializer = TaskSerializer(task, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return {
                        'ErrorCode': error_codes.SUCCESS,
                        'SuccessMSG': error_codes.TASK_UPDATED,
                        'TaskData': {
                            'id': task.id,
                            **serializer.data
                        }
                    }
                else:
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': serializer.errors
                    }
            elif request.user.role == 'user' and task.assigned_to == str(request.user):
                print('finally inside')
                status = request.data.get('status')
                tags = request.data.get('tags',[])
                if not status and not tags:
                    return{
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.UPDATE_CONSTRAINTS
                    }
                else:
                    if status:
                        task.status = status
                    if tags:
                        tagIds = []
                        for tagName in tags:
                            if tagName:
                                tag, created = Tag.objects.get_or_create(name=tagName)
                                print('Tag is: ', tag)
                                tagIds.append(tag.id)
                        task.tags.set(tagIds)
                        task.save()
                        return {
                            'ErrorCode': error_codes.SUCCESS,
                            'SuccessMSG': error_codes.TASK_UPDATED,
                            'TaskData': TaskSerializer(task).data
                        }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.UNAUTHORIZED_TO_UPDATE_TASK
                }
        
        except Task.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
            }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }


    def delete(self, request, task_id):
        try:
            task = Task.objects.get(id=task_id)
            if request.user.role == 'admin':
                task.delete()
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'SuccessMSG': error_codes.TASK_DELETED,
                    'TaskData': TaskSerializer(task).data
                }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.UNAUTHORIZED_TO_DELETE_TASK
                }
        except Task.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
            }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        

class Filters():
    def category(self, request):
        try:
            category = request.GET.get('category', '')
            if category:
                if request.user.role == 'admin':
                    tasks = Task.objects.filter(category=category)
                    if tasks.exists():
                        serializer = TaskSerializer(tasks, many=True)
                        print('before returning successful response')
                        return{
                            'ErrorCode': error_codes.SUCCESS,
                            'SuccessMSG': f'Tasks with category {category}',
                            'TaskData': serializer.data
                        }
                    else:
                        return{
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': f'No tasks found with category: {category}'
                        }
                elif request.user.role == 'user':
                    if Task.objects.filter(assigned_to=request.user).exists():
                        tasks = Task.objects.filter(assigned_to=request.user, category=category)
                        if tasks.exists():
                            serializer = TaskSerializer(tasks, many=True)
                            return {
                                'ErrorCode': error_codes.SUCCESS,
                                'SuccessMSG': f'Tasks with category {category}',
                                'TaskData': serializer.data
                            }
                        else:
                            return{
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': f'No tasks found with category: {category}'
                        }
                    else:
                        return {
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': error_codes.NO_TASK_ASSIGNED_TO_LOGGED_IN_USER
                        }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.CATEGORY_PARAMETER_IS_REQUIRED
                }
            
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }


    def priority(self, request):
        try:
            priority = request.GET.get('priority', '')
            if priority:
                if request.user.role == 'admin':
                    tasks = Task.objects.filter(priority=priority)
                    if tasks.exists():
                        serializer = TaskSerializer(tasks, many=True)
                        print('before returning successful response')
                        return{
                            'ErrorCode': error_codes.SUCCESS,
                            'SuccessMSG': f'Tasks with priority {priority}',
                            'TaskData': serializer.data
                        }
                    else:
                        return{
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': f'No tasks found with priority: {priority}'
                        }
                elif request.user.role == 'user':
                    if Task.objects.filter(assigned_to=request.user).exists():
                        tasks = Task.objects.filter(assigned_to=request.user, priority=priority)
                        if tasks.exists():
                            serializer = TaskSerializer(tasks, many=True)
                            return {
                                'ErrorCode': error_codes.SUCCESS,
                                'SuccessMSG': f'Tasks with priority {priority}',
                                'TaskData': serializer.data
                            }
                        else:
                            return{
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': f'No tasks found with priority: {priority}'
                        }
                    else:
                        return {
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': error_codes.NO_TASK_ASSIGNED_TO_LOGGED_IN_USER
                        }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.PRIORITY_PARAMETER_IS_REQUIRED
                }
            
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        
    def searchFilter(self, request):
        try:
            tasks = []
            keyword = request.GET.get('search', '')
            
            if request.user.role == 'admin':
                print('inside search middleware')
                tasks = Task.objects.filter(Q(title__icontains=keyword) | Q(description__icontains=keyword))
                if tasks.exists():
                    serializer = TaskSerializer(tasks, many=True)
                    print('before returning response')
                    return {
                        'ErrorCode': error_codes.SUCCESS,
                        'Tasks': serializer.data
                    }
                else:
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
                    }

            elif request.user.role == 'user':
                if Task.objects.filter(assigned_to=request.user.username).exists():
                    tasks = Task.objects.filter(
                        Q(assigned_to=request.user.username) &
                        (Q(title__icontains=keyword) | Q(description__icontains=keyword))
                    )
                    if tasks.exists():
                        serializer = TaskSerializer(tasks, many=True)
                        return {
                            'ErrorCode': error_codes.SUCCESS,
                            'Tasks': serializer.data
                        }
                    else:
                        return {
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': f'No task assigned to this user with the search term "{keyword}"'
                        }
                else:
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.NO_TASK_ASSIGNED_TO_LOGGED_IN_USER
                    }

        except Exception as e:
            print('straight in exception')
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        

    def filterByTag(self, request):
        try:
            tag_name = request.GET.get('tags', '')
            tag = Tag.objects.get(name=tag_name)
            
            tasks = [] 

            if request.user.role == 'admin':
                tasks = Task.objects.filter(tags=tag)
            
            elif request.user.role == 'user':
                tasks = Task.objects.filter(assigned_to=request.user.username, tags=tag)

            if tasks.exists():
                serializer = TaskSerializer(tasks, many=True)
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'Task Data': serializer.data
                }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': f'No tasks found for the tag "{tag_name}" for this user.'
                }

        except Tag.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.TAG_DOES_NOT_EXIST
            }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }

class Comments():
    def addComment(self, request, taskId):
        try:
            task = Task.objects.get(id=taskId)
            content = request.data.get('content')
            if request.user.role == 'admin':
                if not content:
                    return {
                        'ErrorCode': error_codes.ERROR, 
                        'ErrorMSG': error_codes.NO_CONTENT
                        }
                comment = Comment.objects.create(task=task,user=request.user, content=content)
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'SuccessMSG': error_codes.COMMENT_ADDED_SUCCESSFULLY, 
                    'CommentData': CommentSerializer(comment).data
                    }
            elif request.user.role == 'user':
                if task.assigned_to != str(request.user):
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.UNAUTHORIZED_TO_ADD_COMMENT
                    }

            if not content:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.NO_CONTENT
                }
            comment = Comment.objects.create(task=task, user=request.user, content=content)
            return {
                'ErrorCode': error_codes.SUCCESS,
                'SuccessMSG': error_codes.COMMENT_ADDED_SUCCESSFULLY,
                'CommentData': CommentSerializer(comment).data
            }
        except Task.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
                }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        

    def viewComment(self, request, taskId):
        try:
            task = Task.objects.get(id=taskId)
            if request.user.role == 'admin':
                comments = task.comments.all()

            elif request.user.role == 'user':
                if task.assigned_to != str(request.user):
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.UNAUTHORIZED_TO_VIEW_COMMENT
                    }
                comments = task.comments.all()
            return {
                'ErrorCode': error_codes.SUCCESS,
                'Comments': CommentSerializer(comments, many=True).data
                }
        except Task.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
            }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': str(e)
                }
        

class Subtasks():
    def createSubtask(self, request, taskId):
        try:
            parentTask = Task.objects.get(id=taskId)
            if parentTask:
                if request.user.role == 'admin' or request.user.role == 'user' and parentTask.assigned_to == str(request.user):
                    serializer = SubtaskSerializer(data=request.data)
                    if serializer.is_valid():
                        serializer.save(parent_task=parentTask)
                        return {
                            'ErrorCode': error_codes.SUCCESS,
                            'SuccessMSG': error_codes.SUBTASK_CREATED,
                            'Subtask Data': serializer.data
                        }
                    else:
                        return {
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': serializer.errors
                        }
                else:
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.UNAUTHORIZED_TO_CREATE_SUBTASK
                    }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
                }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        
    def listSubtasks(self, request, taskId):
        try:
            task = Task.objects.get(id=taskId)
            if request.user.role == 'admin' or (request.user.role == 'user' and task.assigned_to == str(request.user)):
                subtasks = Subtask.objects.get(parent_task=task)
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'Subtasks': SubtaskSerializer(subtasks).data
                }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.UNAUTHORIZED_TO_VIEW_SUBTASK
                }
        except Task.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
            }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': str(e)
            }
        


class Tracking():
    def statusTracking(self, request, taskId):
        try:
            task = Task.objects.get(id=taskId)
            if request.user.role == 'admin' or request.user.role == 'user' and task.assigned_to == str(request.user):
                status = request.data.get('status')
                if status not in Task.StatusChoices.values:
                    return{
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.INVALID_STATUS_VALUE
                    }
                task.status = status
                task.save()
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'SuccessMSG': error_codes.TASK_STATUS_UPDATED_SUCCESSFULLY,
                    'TaskData': TaskSerializer(task).data
                }
            else:
                return {
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.UNAUTHORIZED_TO_UPDATE_TASK_STATUS
                }
        except Task.DoesNotExist:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
            }
        except Exception as e:
            return {
                'ErrorCode': error_codes.ERROR, 
                'ErrorMSG': str(e)
            }
        

class DueDate():
    def dueDateExtension(self, request, taskId):
        try:
            if request.user.role == 'admin':
                return{
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.REQUESTED_DATE_USER_ID_ADMIN
                }
            else:
                task = Task.objects.get(id=taskId)
                if task:
                    if task.assigned_to == str(request.user):
                        dueDate = request.data.get('requested_date')
                        if not dueDate:
                            return {
                                'ErrorCode': error_codes.ERROR,
                                'ErrorMSG': error_codes.REQUESTED_DUE_DATE_IS_REQ
                            }
                        print(task)
                        print(request.user)
                        extensionRequest = DueDateExtensionRequest.objects.create(task=task, user=request.user, requested_date=dueDate)
                        serializer = DueDateExtensionRequestSerializer(extensionRequest)
                        return {
                            'ErrorCode': error_codes.SUCCESS,
                            'SuccessMSG': error_codes.EXTENSION_REQ_SUBMITTED,
                            'Extension Request': serializer.data
                        }
                    else:
                        return {
                            'ErrorCode': error_codes.ERROR,
                            'ErrorMSG': error_codes.USER_NOT_AUTHORIZED_TO_REQUEST_EXTENSION_DATE
                        }
                else:
                    return {
                        'ErrorCode': error_codes.ERROR,
                        'ErrorMSG': error_codes.TASK_DOES_NOT_EXIST
                    }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }
        



class Dashboard():
    def dashboard(self, request):
        try:
            if request.user.role == 'admin':
                currentDate = timezone.now().date()
                totalTasks = Task.objects.count()
                tasksByStatus = {
                    'Pending': Task.objects.filter(status='Pending').count(),
                    'In Progress': Task.objects.filter(status='In Progress').count(),
                    'Completed': Task.objects.filter(status='Completed').count(),
                    'On Hold': Task.objects.filter(status='On Hold').count(),
                }
                tasksByPriority = {
                    'High': Task.objects.filter(priority='High').count(),
                    'Medium': Task.objects.filter(priority='Medium').count(),
                    'Low': Task.objects.filter(priority='Low').count(),
                }
                tasksByCategory = {
                    'Work': Task.objects.filter(category='Work').count(),
                    'Personal': Task.objects.filter(category='Personal').count(),
                    'Fitness': Task.objects.filter(category='Fitness').count(),
                }
                completedTask = Task.objects.filter(status='Completed').count()
                pendingTask = Task.objects.filter(status='Pending', due_date__gte=currentDate).count()
                overdueTask = Task.objects.filter(is_completed=False, due_date__lt=currentDate).count()
                return {
                    'ErrorCode': error_codes.SUCCESS,
                    'SuccessMSG': error_codes.DASHBOARD_STATS,
                    'Total Tasks': totalTasks,
                    'Tasks by Status': tasksByStatus,
                    'Tasks by Priority': tasksByPriority,
                    'Tasks by Category': tasksByCategory,
                    'Tasks Completed': completedTask,
                    'Tasks Pending': pendingTask,
                    'Tasks Overdue': overdueTask
                }
            else:
                return{
                    'ErrorCode': error_codes.ERROR,
                    'ErrorMSG': error_codes.UNAUTHORIZED_TO_ACCESS_DASHBOARD
                }
        except Exception as e:
            return{
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            }