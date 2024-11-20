from django.shortcuts import render
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import permission_classes, authentication_classes, api_view, renderer_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from . serializers import UserRegistrationSerializer, LoginSerializer
from .core import error_codes
from .middleware.middleware import RegLogin, CRUD, Filters, Comments, Subtasks, Tracking, DueDate, Dashboard
from django.core.exceptions import ObjectDoesNotExist
from .models import Task, Comment
from .serializers import TaskSerializer, CommentSerializer
# Create your views here.
from rest_framework import response, schemas

from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer


#should search and filters require User authentication.
#status as an ENUM field.



####################################################### START OF AUTH API'S #########################################################

@api_view(['POST'])
def UserRegister(request):
    try:
        serializer= UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            obj = RegLogin()
            result = obj.UserReg(validated_data)
            return Response(result)
        else:
            return Response({'ErrorCode': 1, 'ErrorMSG': serializer.errors})
    except Exception as e:
        return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            })
    



@api_view(['POST'])
def UserLogin(request):
    try:
        print('inside login')
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            obj = RegLogin()
            result = obj.UserLog(validated_data, request)
            return Response(result)
        else:
            return Response({'ErrorCode': error_codes.ERROR, 'ErrorMSG': serializer.errors})
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def Logout(request):
    try:
        if request.user.is_authenticated:
            obj = RegLogin()
            result = obj.logout(request)
            return Response(result)
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })




####################################################### END OF AUTH API'S #########################################################




####################################################### START OF CRUD API'S #########################################################


@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@api_view(['POST'])
def createTask(request):
    try:
        print('in view')
        if request.user.is_authenticated:
            obj = CRUD()
            print('before calling middleware')
            result = obj.create(request)
            return Response(result)
        else:
            print('user not authenticated')
            return Response({'ErrorCode': error_codes.ERROR,'ErrorMSG': error_codes.UNAUTHORIZED})
    except Exception as e:
            print('inside exception')
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': str(e)
            })


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def readAllTasks(request):
    try:
        if request.user.is_authenticated:
           obj = CRUD()
           result = obj.readAll(request)
           return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        context = {'ErrorCode': error_codes.ERROR, 'ErrorMsg': str(e)}
        return Response(context)
    

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def readOneTask(request, taskId):
    try:
        print('inside read one task')
        if request.user.is_authenticated:
           obj = CRUD()
           result = obj.readOne(request, taskId)
           return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        context = {'ErrorCode': error_codes.ERROR, 'ErrorMsg': str(e)}
        return Response(context)



@api_view(['PUT'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def updateTask(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = CRUD()
            result = obj.update(request, taskId)
            return Response(result)
        else:
            return Response({'ErrorCode': error_codes.ERROR, 'ErrorMSG': error_codes.UNAUTHORIZED})
    except Exception as e:
        return Response({
            'ErrorCode': 'ERROR',
            'ErrorMSG': str(e)
        })
    

@api_view(['DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def deleteTask(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = CRUD()
            result = obj.delete(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })





    ####################################################### END OF CRUD API'S #########################################################







   ####################################################### START OF FILTER AND SEARCH API'S #########################################################






    ####################################################### PRIORITY FILTER API #########################################################

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def priorityFilter(request):
    try:
        if request.user.is_authenticated:
            obj = Filters()
            result = obj.priority(request)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
        



    ####################################################### CATEGORY FILTER API #########################################################


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def categoryFilter(request):
    try:
        if request.user.is_authenticated:
            obj = Filters()
            result = obj.category(request)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def search(request):
    try:
        if request.user.is_authenticated:
            obj = Filters()
            result = obj.searchFilter(request)
            print('result is: ',result)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def tags(request):
    try:
        if request.user.is_authenticated:
            obj = Filters()
            result = obj.filterByTag(request)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    



   ####################################################### END OF FILTER AND SEARCH API'S #########################################################







    ####################################################### START OF TASK COMMENTS API'S #########################################################




@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def addComment(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = Comments()
            result = obj.addComment(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR, 
            'ErrorMSG': str(e)
        })
    



@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def viewComment(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = Comments()
            result = obj.viewComment(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR, 
            'ErrorMSG': str(e)
        })
    



    ####################################################### END OF TASK COMMENTS API'S #########################################################




    ####################################################### START OF SUBTASK API'S #########################################################

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def createSubtask(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = Subtasks()
            result = obj.createSubtask(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def viewSubtask(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = Subtasks()
            result = obj.listSubtasks(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    


        ####################################################### END OF SUBTASK API'S #########################################################





    ####################################################### STATUS TRACKING API #########################################################
@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def trackStatus(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = Tracking()
            result = obj.statusTracking(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    



    ####################################################### DUE DATE EXTENSION REQUEST API #########################################################


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def duedateExtension(request, taskId):
    try:
        if request.user.is_authenticated:
            obj = DueDate()
            result = obj.dueDateExtension(request, taskId)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })
    




    ####################################################### STATS DASHBOARD API #########################################################





@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def dashboard(request):
    try:
        if request.user.is_authenticated:
            obj = Dashboard()
            result = obj.dashboard(request)
            return Response(result)
        else:
            return Response({
                'ErrorCode': error_codes.ERROR,
                'ErrorMSG': error_codes.UNAUTHORIZED
            })
    except Exception as e:
        return Response({
            'ErrorCode': error_codes.ERROR,
            'ErrorMSG': str(e)
        })