from rest_framework import generics, permissions
from base.models import *
from .serializers import *
from django.http import JsonResponse, HttpResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status, filters
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.exceptions import PermissionDenied
from datetime import timedelta
from datetime import date
import datetime
from base.api import smtp_mail
import string
import random
import os
from django.db.models import Q, Max
from . import updater
from django.db import transaction
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models import F
import json
from django.forms.models import model_to_dict


@api_view(["GET"])
def getRoutes(request):
    routes = [
        "/api/token",
        "/api/ssotoken"
        "/api/token/refresh",
    ]

    return Response(routes)

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        group = user.groups.filter(user=user).values().first()
        # Add custom claims
        token["username"] = user.username
        token["is_superuser"] = user.is_superuser
        if token["is_superuser"]:
            token["role"] = 1
        else:
            token["role"] = group['id']
        # ...

        return token

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        try:
            username = request.data.get("username")
            sso = request.data.get("sso")

            response = super().post(request, *args, **kwargs)

            if sso:
                return response
            else:
                json_data = ConvertQuerysetToJson(User.objects.filter(username=username))
                staff = json_data.get("is_staff")
                if staff == True:
                    return response
                else:
                    raise PermissionDenied("User is not staff and cannot generate a token.")
        except Exception as e:
                return Response({'error' : str(e)}, status=status.HTTP_204_NO_CONTENT)

# SSO Token Generator API Class
class MySSOTokenObtainPairView(TokenObtainPairView):
    # serializer_class = MyTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        try:
            if email:
                user = User.objects.filter(email=email).first()
                if user:
                    refresh = RefreshToken.for_user(user)
                    
                    # Add custom claims from your serializer logic (username, is_superuser, role)
                    refresh['username'] = user.username
                    refresh['is_superuser'] = user.is_superuser

                    group = user.groups.filter(user=user).values().first()
                    if user.is_superuser:
                        refresh['role'] = 1
                    else:
                        refresh['role'] = group['id'] if group else None
                    
                    return Response({
                            'refresh': str(refresh),
                            'access': str(refresh.access_token),
                        }, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'No user found with the given email'}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            
# Update user active

class UpdateActiveView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdateActiveSerializer


# Create super user

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_users(request):

    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if User.objects.filter(username=username):
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    users = User.objects.create_user(username, email, password, is_staff=1)
    temp = User.objects.filter(username=users)
    return Response("User Added successfully", status=status.HTTP_200_OK)

# Create super user

@api_view(["POST"])
def ms_save_users(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if User.objects.filter(username=username):
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    users = User.objects.create_user(username, email, password)
    temp = User.objects.filter(username=users)
    return Response("User Added successfully", status=status.HTTP_200_OK)
    
# Get Auth Group

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_auth_group(request):
    auth_group = Group.objects.all()
    serializer = auth_group_serializer(auth_group, many=True)
    return Response(serializer.data)


def ConvertQuerysetToJson(qs):
    if qs == None:
        return "Please provide valid Django QuerySet"
    else:
        json_data = {}
        for i in qs:
            i = i.__dict__
            i.pop("_state")
            json_data.update(i)
    return json_data

# Get User Group details range

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_user_groups(request, start, end):
    try:
        group_user_dict = {
            group.id: group.user_set.values_list(
                "id", "username", "email", "is_active", flat=False
            )
            for group in Group.objects.all()
        }
        act_json = []
        for i in group_user_dict:
            temp = ConvertQuerysetToJson(Group.objects.filter(id=i))

            for j in group_user_dict[i]:
                
                temp_json = {
                    "user_id": j[0],
                    "user_name": j[1],
                    "user_mail": j[2],
                    "is_active": j[3],
                    "user_group_id": i,
                    "user_group_name": temp["name"],
                }
                act_json.append(temp_json)

    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)

    return Response({"data": act_json[start:end], "data_length": len(act_json)})

# Get User Group details

@api_view(['POST', 'GET'])
# @permission_classes([IsAuthenticated])
def get_user_groups(request, id=0):
    try:
        superadmin = True
        # request.data.get('is_superuser') 
        if id == 0:
            group_user_dict = {
                group.id: group.user_set.values_list(
                    "id", "username", "email", "is_active", "is_staff", flat=False
                )
                for group in Group.objects.all()
            }
        else:
            group_user_dict = {
                group.id: User.objects.filter(id=id).values_list(
                    "id", "username", "email", "is_active", "is_staff", flat=False
                ) if superadmin else group.user_set.filter(id=id).values_list(
                    "id", "username", "email", "is_active", "is_staff", flat=False
                )
                for group in Group.objects.all()
            }
        act_json = []
        for i in group_user_dict:
            temp = ConvertQuerysetToJson(Group.objects.filter(id=i))
            for j in group_user_dict[i]:
                temp_json = {
                    "user_id": j[0],
                    "user_name": j[1],
                    "user_mail": j[2],
                    "is_active": j[3],
                    "is_staff": j[4],
                    "user_group_id": i,
                    "user_group_name": temp["name"],
                }
                act_json.append(temp_json)
    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)

    return Response(act_json, status=status.HTTP_200_OK)

# Create user groups add

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_user_groups(request):
    user_id = request.data.get("user_id")
    group_id = request.data.get("group_id")

    user = User.objects.get(id=user_id)
    group = Group.objects.get(id=group_id)
    user.groups.add(group)

    return Response("User Added successfully", status=status.HTTP_200_OK)

# Create user groups add

@api_view(["POST"])
def ms_ins_user_groups(request):
    user_id = request.data.get("user_id")
    group_id = request.data.get("group_id")

    user = User.objects.get(id=user_id)
    group = Group.objects.get(id=group_id)

    user.groups.add(group)

    return Response("User Added successfully", status=status.HTTP_200_OK)

# Create user groups Update
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_user_groups(request):
    user_id = request.data.get("id")
    user_name = request.data.get("username")
    first_name = request.data.get("first_name")
    last_name = request.data.get("last_name")
    user_mail = request.data.get("email")
    group_id = request.data.get("group")
    user = User.objects.get(id=user_id)
    group = Group.objects.get(id=group_id)
    if User.objects.filter(username=user_name).exclude(id=user_id):
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    user.groups.set([group])
    user.email = user_mail
    user.username = user_name
    user.first_name = first_name
    user.last_name = last_name
    user.is_active = 1 if request.data.get("is_active") else 0
    user.save()

    return Response("User Updated successfully", status=status.HTTP_200_OK)


# updatig single given column
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
@transaction.atomic
def upd_user_column(request, id):
    ReqData = request.data

    try:
        user = User.objects.get(id=id)  # Fetch user once
        item = user_profile.objects.get(user_id=id)
        item_dict = model_to_dict(item)

        print(item_dict) 

        for key, value in ReqData.items():
            if key == "user_group":
                group = Group.objects.get(id=int(value))
                user.groups.set([group])
                if hasattr(item, key):  
                    setattr(item, key, value)
                else:
                    return Response({"error": f"Invalid field: {key}"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                if hasattr(item, key): 
                    setattr(item, key, value)
                else:
                    return Response({"error": f"Invalid field: {key}"}, status=status.HTTP_400_BAD_REQUEST)
        user.save()
        item.save()

        return Response("User updated successfully", status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Group.DoesNotExist:
        return Response({"error": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Join group and group_access_definition table view
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def group_group_access(request, id=0, menu_id=0):
    if id == 0:
        org = navigation_menu_details.objects.filter(delete_flag=False)
        serializer = navigation_menu_details_serializer(org, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        if menu_id == 0:
            reports = group_access_definition.objects.select_related("group_id").filter(group_id=id)
        else:
            superadmin = User.objects.filter(id=id).values('is_superuser')
            grp_id = ConvertQuerysetToJson(User.objects.get(id=id).groups.all())
            if superadmin[0]['is_superuser']:
                reports = group_access_definition.objects.select_related(
                    "group_id", "menu_id"
                ).filter(group_id=1, menu_id=menu_id)
            else:
                reports = group_access_definition.objects.select_related(
                "group_id", "menu_id"
                ).filter(group_id=grp_id["id"], menu_id=menu_id)
            # reports = group_access_definition.objects.select_related("group_id").filter(group_id=id, menu_id=menu_id)
        data = group_group_access_serializer(
            reports, many=True, context={"request": request}
        ).data
        return Response(data, status=status.HTTP_200_OK)
    
# SMTP

@api_view(["GET"])
def get_smtp(request):
    data = smtp_configure_serializer(
        smtp_configure.objects.filter(delete_flag=False), many=True
    ).data
    return Response(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_upt_smtp(request):
    listData = request.data
    for i in range(len(listData)):
        data = {
            "user_id": listData[i]["user_id"],
            "server_name": listData[i]["server_name"],
            "username": listData[i]["username"],
            "password": listData[i]["password"],
            "protocol": listData[i]["protocol"],
            "port": listData[i]["port"],
            "created_by": listData[i]["created_by"],
            "last_updated_by": listData[i]["last_updated_by"],
        }
        if "id" in listData[i]:
            item = smtp_configure.objects.get(id=listData[i]["id"])
            serializer = smtp_configure_serializer(instance=item, data=data)
            to = listData[i]["username"]
            subject = "SMTP Configuration Updated"
            body = f"""
            <html>
            <head>
            <style>
                .email-container {{
                    font-family: Arial, sans-serif;
                    max-width: 600px;
                    margin: auto;
                    border: 1px solid #eaeaea;
                    border-radius: 8px;
                    padding: 20px;
                    background-color: #f9f9f9;
                }}
                .header {{
                    text-align: center;
                    padding-bottom: 20px;
                }}
                .header img {{
                    width: 80px;
                }}
                .content {{
                    text-align: left;
                    font-size: 16px;
                    color: #333333;
                    line-height: 1; /* Reduced line spacing */
                }}
                .success-icon {{
                    display: block;
                    margin: 20px auto;
                    width: 50px;
                }}
                .note {{
                    font-size: 14px; /* Smaller font size for the note */
                    color: #666666;
                    margin-top: 15px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 20px;
                    font-size: 12px;
                    color: #aaaaaa;
                }}
            </style>
            </head>
            <body>
            <div class="email-container">
                <div class="header">
                    <img src="https://cdn-icons-png.flaticon.com/128/190/190411.png" alt="Success Icon" class="success-icon" />
                    <h2>SMTP Configuration Updated Successfully</h2>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>Your SMTP configuration details have been successfully updated.</p>
                    <p>Email: {listData[i]["username"][:3]}****@{listData[i]["username"].split('@')[-1]}</p>
                    <p>You can now use the updated configuration without any issues.</p>
                    <p class="note"><b>Note:</b> This is an automated email, please do not reply.</p>
                </div>
                <div class="footer">
                    <p>© 2024 Copyright Cittabase Solutions. All rights reserved.</p>
                </div>
            </div>
            </body>
            </html>
            """
            attachments = ""

            mail_res = smtp_mail.send_mail(
                to=to,
                body=body,
                subject=subject,
                type="html",
                attachments="",
                filename="",
                filepath="",
                test=[data],
            )
            if mail_res == "true":
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                print("Er 1")
                return Response(
                    "Failed to connect smtp server. Please check your details",
                    status=status.HTTP_400_BAD_REQUEST,
                )

        else:
            to = listData[i]["username"]
            subject = "SMTP Configuration Successful"
            body = f"""
            <html>
                <head>
                <style>
                    .email-container {{
                        font-family: Arial, sans-serif;
                        max-width: 600px;
                        margin: auto;
                        border: 1px solid #eaeaea;
                        border-radius: 8px;
                        padding: 20px;
                        background-color: #f9f9f9;
                    }}
                    .header {{
                        text-align: center;
                        padding-bottom: 20px;
                    }}
                    .header img {{
                        width: 80px;
                    }}
                    .content {{
                        text-align: left;
                        font-size: 16px;
                        color: #333333;
                        line-height: 1; /* Reduced line spacing */
                    }}
                    .success-icon {{
                        display: block;
                        margin: 20px auto;
                        width: 50px;
                    }}
                    .note {{
                        font-size: 14px; /* Smaller font size for the note */
                        color: #666666;
                        margin-top: 15px;
                    }}
                    .footer {{
                        text-align: center;
                        margin-top: 20px;
                        font-size: 12px;
                        color: #aaaaaa;
                    }}
                </style>
                </head>
                <body>
                <div class="email-container">
                    <div class="header">
                        <img src="https://cdn-icons-png.flaticon.com/128/190/190411.png" alt="Success Icon" class="success-icon" />
                        <h2>SMTP Configuration Successful</h2>
                    </div>
                    <div class="content">
                        <p>Hello,</p>
                        <p>Your SMTP credentials have been successfully configured.</p>
                        <p>Email: {listData[i]["username"][:3]}****@{listData[i]["username"].split('@')[-1]}</p>
                        <p>You can now use this email configuration without any issues.</p>
                        <p class="note"><b>Note:</b> This is an automated email, please do not reply.</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 Copyright Cittabase Solutions. All rights reserved.</p>
                    </div>
                </div>
                </body>
                </html>
                """
            attachments = ""

            mail_res = smtp_mail.send_mail(
                to=to,
                body=body,
                subject=subject,
                type="html",
                attachments="",
                filename="",
                filepath="",
                test=[data],
            )
            if mail_res == "true":
                serializer = smtp_configure_serializer(data=data)
                
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response(
                    "Serialier Error",
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    "Failed to connect smtp server. Please check your details",
                    status=status.HTTP_400_BAD_REQUEST,
                )

# Forgot Password

@api_view(["POST"])
def forgot_password(request):
    email = request.data
    check_email = ConvertQuerysetToJson(User.objects.filter(email=email, is_active=1))
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    numbers = string.digits
    special_characters = string.punctuation

    if check_email:
        combinedPassword = (
            random.choice(uppercase_letters)
            + random.choice(lowercase_letters)
            + random.choice(numbers)
            + random.choice(special_characters)
        )

        randomPassword = "".join(
            random.choice(lowercase_letters) + random.choice(uppercase_letters)
            for _ in range(len(combinedPassword) + 1)
        )

        subject = "Password reset"
        body = f"""
            <html>
                <head>
                <style>
                    .email-container {{
                        font-family: Arial, sans-serif;
                        max-width: 600px;
                        margin: auto;
                        border: 1px solid #eaeaea;
                        border-radius: 8px;
                        padding: 20px;
                        background-color: #f9f9f9;
                    }}
                    .header {{
                        text-align: center;
                        padding-bottom: 20px;
                    }}
                    .header img {{
                        width: 80px;
                    }}
                    .content {{
                        text-align: left;
                        font-size: 16px;
                        color: #333333;
                        line-height: 1.5;
                    }}
                    .success-icon {{
                        display: block;
                        margin: 20px auto;
                        width: 50px;
                    }}
                    .password-box {{
                        font-size: 18px;
                        font-weight: bold;
                        color: #ffffff;
                        background-color: #007BFF;
                        display: inline-block;
                        padding: 10px 20px;
                        border-radius: 5px;
                        text-align: center;
                        margin: 20px 0;
                    }}
                    .note {{
                        font-size: 14px;
                        color: #666666;
                        margin-top: 15px;
                    }}
                    .footer {{
                        text-align: center;
                        margin-top: 20px;
                        font-size: 12px;
                        color: #aaaaaa;
                    }}
                </style>
                </head>
                <body>
                <div class="email-container">
                    <div class="header">
                        <img src="https://cdn-icons-png.flaticon.com/128/709/709699.png" alt="Password Icon" class="success-icon" />
                        <h2>Password Reset Successful</h2>
                    </div>
                    <div class="content">
                        <p>Hello <strong>{check_email["username"].capitalize()}</strong>,</p>
                        <p>Your password has been successfully reset. Please use the password below to log in to your account:</p>
                        <p class="password-box">{randomPassword}</p>
                        <p>If you did not request this password reset, please contact our support team immediately.</p>
                        <p class="note"><b>Note:</b> This is an automated email, please do not reply.</p>
                    </div>
                    <div class="footer">
                        <p>© 2024 Copyright Cittabase Solutions. All rights reserved.</p>
                    </div>
                </div>
                </body>
            </html>
            """


        u = User.objects.get(id=check_email["id"])
        u.set_password(randomPassword)
        u.save()
        mail_res = smtp_mail.send_mail(
            to=email, subject=subject, body=body, type="html"
        )
        return Response(status=status.HTTP_200_OK)
    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)

# license Update

@api_view(["PUT"])
def ins_upd_license(request, id):
    item = user_license.objects.filter(user_id=id)
    data = {
        "license_key": request.data.get("key"),
        "user_id": id,
        "created_by": id,
        "last_updated_by": id,
    }
    if len(item) == 0:
        serializer = user_license_serializer(data=data)
    else:
        exist = user_license.objects.get(user_id=id)
        serializer = user_license_serializer(instance=exist, data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response (serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# License key

@api_view(["GET"])
def get_license(request):
    current_datetime = datetime.datetime.now().date()
    licensed = user_license.objects.filter(delete_flag=False)
    serializer = user_license_serializer(licensed, many=True)
    return Response(
        {"data": serializer.data, "current_date": current_datetime},
        status=status.HTTP_200_OK,
    )

# Update Session

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def updatesession(request, uid=0, update=""):
    item = request.data
    now = datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S")
    expiredOneday = datetime.datetime.strptime(now, "%Y-%m-%d %H:%M:%S") + timedelta(hours=24)
    count_session = session.objects.filter(uid=uid, status=1)
    if update == "update":
        try:
            data = {
                "uid": uid,
                "sid": item["access"],
                "expired": expiredOneday.strftime("%Y-%m-%d %H:%M:%S"),
                "status": 1,
            }
            exist_session = session.objects.get(uid=uid, sid=item["prev_token"])
            serializer = session_serializer(instance=exist_session, data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(status=status.HTTP_201_CREATED)
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(e, status=status.HTTP_200_OK)
    elif update == "close":
        cdata = {
            "lasttime": item["last_time"],
            "status": 0,
        }
        exist_session = session.objects.filter(uid=uid, sid=item["access"]).update(lasttime=item["last_time"], status=0)
        if exist_session:
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
    elif update == "shotdown":
        exist_session = session.objects.filter(uid=uid, sid=item["access"]).update(
            lasttime=item["last_time"]
        )
        if exist_session:
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
    else:
        if len(count_session) < 10:
            data = {
                "uid": uid,
                "sid": item["access"],
                "logintime": item["login_time"],
                "expired": expiredOneday.strftime("%Y-%m-%d %H:%M:%S"),
                "status": 1,
            }
            serializer = session_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(status=status.HTTP_200_OK)
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)

# Delete Session

@api_view(["PUT"])
def deletesession(request, uid=0):
    exist_session = session.objects.filter(uid=uid).update(sta=item["last_time"])
    if exist_session:
        return Response(status=status.HTTP_201_CREATED)
    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)

def session_active_check():
    active_session = session.objects.filter(status=1).values()
    for i in active_session:
        current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if i["expired"] < current_date:
            exist_session = session.objects.filter(uid=i["uid"], sid=i["sid"]).update(
                status=0
            )
    return Response(status=status.HTTP_200_OK)

# Session Configuration

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_session_configuration(request):
    sessionData = session_configuration.objects.filter(delete_flag=False)
    serializer = session_configuration_serializer(sessionData, many=True)
    return Response(serializer.data)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_upd_session_configuration(request, id):
    if id == 0:
        data = {
        "idle_time": request.data.get("idle_time"),
        "session_time": request.data.get("session_time"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
        }
        serializer = session_configuration_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
    else:
        data = {
            "idle_time": request.data.get("idle_time"),
            "session_time": request.data.get("session_time"),
            "last_updated_by": request.data.get("last_updated_by"),
        }
        exist_session = session_configuration.objects.get(id=id, delete_flag=False)
        serializer = session_configuration_serializer(instance=exist_session, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# SSO Insert

@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def ins_sso(request):
    data = {
        "app_id": request.data.get("app_id"),
        "tenant_id": request.data.get("tenant_id"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = sso_configure_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# SSO Get

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_sso(request, id=0):
    if id == 0:
        sso = sso_configure.objects.filter(delete_flag=False)
    else:
        sso = sso_configure.objects.filter(id=id)
    serializer = sso_configure_serializer(sso, many=True)
    return Response(serializer.data)

# SSO Update

@api_view(["PUT"])
# @permission_classes([IsAuthenticated])
def upd_sso(request, id):
    item = sso_configure.objects.get(id=id)
    serializer = sso_configure_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)

# User Profile

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_profile(request, id=0):
    if id == 0:
        user = user_profile.objects.filter(delete_flag=False)
    else:
        user = user_profile.objects.filter(user_id=id)

    serializer = user_profile_serializer(user, many=True)
    
    return Response(serializer.data)

# Add

@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def ins_user_profile(request):
    data = {
        "user_id": request.data.get("user_id"),
        "profile_pic": request.data.get("profile_pic"),
        "temporary_address": request.data.get("temporary_address"),
        "permanent_address": request.data.get("permanent_address"),
        "contact": request.data.get("contact"),
        "user_group": request.data.get("user_group"),
        "user_region": request.data.get("user_region"),
        "user_status": request.data.get("user_status"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }
    if 'profile_pic' not in request.data:
        data["profile_pic"] = None
    serializer = user_profile_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Profile update

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_user_profile(request, id):
    item = user_profile.objects.get(user_id=id)
    data = request.data

    userStatus = 0 if data["user_status"] == 'false' else 1

    if "profile_pic" in data and data["profile_pic"] != 'false':
        profilePic = data["profile_pic"]
    else:
        profilePic = ""

    if item.profile_pic:
        if len(item.profile_pic) > 0 and item.profile_pic != data["profile_pic"]:
            os.remove(item.profile_pic.path)

    if item.profile_pic != profilePic:
        item.profile_pic = profilePic
    if item.temporary_address != data["temporary_address"]:
        item.temporary_address = data["temporary_address"]
    if item.permanent_address != data["permanent_address"]:
        item.permanent_address = data["permanent_address"]
    if item.contact != data["contact"]:
        item.contact = data["contact"]
    if item.user_group != data["user_group"]:
        item.user_group = data["user_group"]
    if item.user_status != userStatus:
        item.user_status = userStatus
    if item.created_by != data["created_by"]:
        item.created_by = data["created_by"]
    if item.last_updated_by != data["last_updated_by"]:
        item.last_updated_by = data["last_updated_by"]
    if item.user_region != data["user_region"]:
        item.user_region = data["user_region"]

    item.save()
    serializer = user_profile_serializer(item)
    return Response(serializer.data)
    
# Delete

@api_view(["PUT"])
# @permission_classes([IsAuthenticated])
def del_user_profile(request, id):
    Userdata = user_profile.objects.get(id=id)
    data = request.data
    print(f"==>> data: {data}")
    if Userdata.delete_flag != data["delete_flag"]:
        Userdata.delete_flag = data["delete_flag"]
    if Userdata.last_updated_by != data["last_updated_by"]:
        Userdata.last_updated_by = data["last_updated_by"]
    Userdata.save()
    serializer = user_profile_serializer(Userdata)
    return Response(serializer.data, status=status.HTTP_200_OK)

# ***Organization definition***


# View all
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_definition(request, id=0):
    if id == 0:
        org = org_definition.objects.filter(delete_flag=False)
    else:
        org = org_definition.objects.filter(id=id)

    serializer = org_definition_serializer(org, many=True)
    return Response(serializer.data)


# Add
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_definition(request):
    data = {
        "organization_name": request.data.get("organization_name"),
        "address_1": request.data.get("address_1"),
        "address_2": request.data.get("address_2"),
        "city": request.data.get("city"),
        "country": request.data.get("country"),
        "state": request.data.get("state"),
        "no_of_org_functional_levels": request.data.get("no_of_org_functional_levels"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }
    serializer = org_definition_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_definition(request, id):
    item = org_definition.objects.get(id=id)
    serializer = org_definition_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


# Delete


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_definition(request, id):
    OrgView = org_definition.objects.get(id=id)
    data = request.data
    if OrgView.delete_flag != data["delete_flag"]:
        OrgView.delete_flag = data["delete_flag"]
    if OrgView.last_updated_by != data["last_updated_by"]:
        OrgView.last_updated_by = data["last_updated_by"]
    OrgView.save()
    serializer = org_definition_serializer(OrgView)
    return Response(serializer.data, status=status.HTTP_200_OK)


# ***Stop light Indicators***

# View all


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_definition_stop_light_indicators(request, id=0):
    if id == 0:
        org = org_definition_stop_light_indicators.objects.filter(delete_flag=False)
    else:
        org = org_definition_stop_light_indicators.objects.filter(id=id)

    serializer = org_definition_stop_light_indicators_serializer(org, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Add


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_definition_stop_light_indicators(request):
    list_data = request.data
    
    for i in range(len(list_data)):
        data = {
            "stop_light_indicator_from": list_data[i]["stop_light_indicator_from"],
            "stop_light_indicator_to": list_data[i]["stop_light_indicator_to"],
            "stop_light_indicator": list_data[i]["stop_light_indicator"],
            "def_id": list_data[i]["def_id"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        serializer = org_definition_stop_light_indicators_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.data, status=status.HTTP_201_CREATED)


# Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_definition_stop_light_indicators(request, id):
    list_data = request.data
    
    for i in range(len(list_data)):
        data = {
            "id": list_data[i]["id"],
            "stop_light_indicator_from": list_data[i]["stop_light_indicator_from"],
            "stop_light_indicator_to": list_data[i]["stop_light_indicator_to"],
            "stop_light_indicator": list_data[i]["stop_light_indicator"],
            "def_id": list_data[i]["def_id"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        
        org_definition_update = org_definition_stop_light_indicators.objects.filter(
            id=list_data[i]["id"]
        ).update(
            stop_light_indicator_from=list_data[i]["stop_light_indicator_from"],
            stop_light_indicator_to=list_data[i]["stop_light_indicator_to"],
            stop_light_indicator=list_data[i]["stop_light_indicator"],
            def_id=list_data[i]["def_id"],
            created_by=list_data[i]["created_by"],
            last_updated_by=list_data[i]["last_updated_by"],
        )

    return Response(org_definition_update, status=status.HTTP_200_OK)


# Delete


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_definition_stop_light_indicators(request, id):
    org_definition_delete = org_definition_stop_light_indicators.objects.filter(
        def_id=id
    ).update(delete_flag=True)
    return Response(org_definition_delete, status=status.HTTP_200_OK)

# Organization Functional Level

# GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_org_functional_level(request, start, end, search=False):
    try:
        if not search:
            org_len = org_functional_level.objects.filter(delete_flag=False).count()
            org_lvl = org_functional_level.objects.filter(delete_flag=False)[start:end]
        else:
            org_len = org_functional_level.objects.filter(Q(hierarchy_level__icontains = search) | Q(hierarchy_name__icontains = search), delete_flag=False).count()
            org_lvl = org_functional_level.objects.filter(Q(hierarchy_level__icontains = search) | Q(hierarchy_name__icontains = search), delete_flag=False)[start:end]
        org_len_withoutfilter = org_functional_level.objects.filter(delete_flag=False).count()
        org_lvl_csv_export = org_functional_level.objects.filter(delete_flag=False)
        serializer = org_functional_level_serializer(org_lvl, many=True)
        serializer_csv_export = org_functional_level_serializer(
            org_lvl_csv_export, many=True
        )
        return Response(
            {
                "data": serializer.data,
                "data_length": org_len,
                "data_length_withoutfilter": org_len_withoutfilter,
                "csv_data": serializer_csv_export.data,
            }
        )
    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)
        

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_functional_level(request, id=0):
    if id == 0:
        org = org_functional_level.objects.filter(delete_flag=False)
    else:
        org = org_functional_level.objects.filter(id=id)

    serializer = org_functional_level_serializer(org, many=True)
    return Response(serializer.data)


# ADD


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_functional_level(request):
    data = {
        "hierarchy_level": request.data.get("hierarchy_level"),
        "hierarchy_name": request.data.get("hierarchy_name"),
        "created_by": request.data.get("created_by"),
        "created_date": request.data.get("created_date"),
        "last_updated_by": request.data.get("last_updated_by"),
        "last_updated_date": request.data.get("last_updated_date"),
    }

    serializer = org_functional_level_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_functional_level(request, id):
    item = org_functional_level.objects.get(id=id)
    serializer = org_functional_level_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


# Delete
@api_view(["PUT"])
def del_org_functional_level(request, id):
    get_heirarchy_level = org_functional_level.objects.filter(id=id, delete_flag=False).values('hierarchy_level')
    if(len(get_heirarchy_level) == 1):
        hierarchy_level = get_heirarchy_level[0]['hierarchy_level']
        check_hierarchy = org_functional_hierarchy.objects.filter(hierarchy_level = get_heirarchy_level[0]['hierarchy_level'], delete_flag=False)
        if len(check_hierarchy) == 0:
            OrgView = org_functional_level.objects.get(id=id)
            data = request.data

            if OrgView.delete_flag != data["delete_flag"]:
                OrgView.delete_flag = data["delete_flag"]

            OrgView.save()

            serializer = org_functional_level_serializer(OrgView)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response("It have contain data under the section", status=status.HTTP_204_NO_CONTENT)
        

# Add Org Fun Hierarchy
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_functional_hierarchy(request):
    data = {
        # 'functional_level_id': request.data.get('functional_level_id'),
        "functional_level_code": request.data.get("functional_level_code"),
        "hierarchy_level": request.data.get("hierarchy_level"),
        "parent_level_id": request.data.get("parent_level_id"),
        "main_parent_id": request.data.get("main_parent_id"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = org_functional_hierarchy_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View all
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_functional_hierarchy(request, id=0):
    if id == 0:
        org = org_functional_hierarchy.objects.filter(delete_flag=False)
    else:
        org = org_functional_hierarchy.objects.filter(id=id)
    serializer = org_functional_hierarchy_serializer(org, many=True)
    return Response(serializer.data)

    # org = org_functional_hierarchy.objects.all()


# Update All
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_functional_hierarchy(request, id):
    org = org_functional_hierarchy.objects.get(pk=id)
    data = org_functional_hierarchy_serializer(instance=org, data=request.data)

    if data.is_valid():
        data.save()
        return Response(data.data, status=status.HTTP_200_OK)
    return Response(data.errors, status=status.HTTP_400_BAD_REQUEST)


# Delete a Single object
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_functional_hierarchy(request, id):
    # for i in range(id,4):
    #     test1 = org_functional_hierarchy.objects.get(parent_level_id=i)
    OrgDelete = org_functional_hierarchy.objects.get(functional_level_id=id)
    data = request.data

    if OrgDelete.delete_flag != data["delete_flag"]:
        OrgDelete.delete_flag = data["delete_flag"]

    OrgDelete.save()
    serializer = org_functional_hierarchy_serializer(OrgDelete)

    # del_data = org_functional_hierarchy.objects.get(id=id).delete()
    return JsonResponse(serializer.data, status=status.HTTP_200_OK)


# Delete a Single object


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_functional_hierarchy_2(request, id_1, id_2, id_3):
    # for i in range(id,4):
    #     test1 = org_functional_hierarchy.objects.get(parent_level_id=i)
    OrgDelete = org_functional_hierarchy.objects.filter(
        main_parent_id=id_1, hierarchy_level__gt=id_2, parent_level_id=id_3
    ).update(delete_flag=True)
    # org = org_functional_hierarchy.objects.get(main_parent_id=id)
    # data = request.data
    # for i in range(0,len(OrgDelete)):
    # serializers =org_functional_hierarchy_serializer(OrgDelete,many=True)

    # if(OrgDelete.delete_flag != data["delete_flag"]):
    #     OrgDelete.delete_flag = data["delete_flag"]

    # OrgDelete.save()
    # serializer = org_functional_hierarchy_serializer(OrgDelete)

    # del_data = org_functional_hierarchy.objects.get(id=id).delete()
    return Response(OrgDelete, status=status.HTTP_200_OK)


# Delete TEST


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_functional_hierarchy_3(request, id_1):
    # Root Hierarchy Level 1
    fun_id_array = []
    fun_id_array.append(id_1)

    # Hierarchy Level 2
    level_2 = org_functional_hierarchy.objects.filter(parent_level_id=id_1)

    for i in range(0, len(level_2)):
        fun_id_array.append(level_2[i].functional_level_id)

    
    # Hierarchy Level N..... Loop Start
    for i in range(0, len(fun_id_array)):
        level = org_functional_hierarchy.objects.filter(
            parent_level_id__in=fun_id_array
        )
        for i in range(0, len(level)):
            fun_id_array.append(level[i].functional_level_id)

        # convert list to set to get unique values alone has a dataset
        set_level = set(fun_id_array)

        # convert the set to the list
        list_level = list(set_level)

    # Loop End

    # Setting Delete flag to Y
    Delete_flag_trigger = org_functional_hierarchy.objects.filter(
        functional_level_id__in=list_level
    ).update(delete_flag=True)

    
    return Response(Delete_flag_trigger, status=status.HTTP_200_OK)


# View all


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_functional_hierarchy_2(request):
    org = org_functional_hierarchy.objects.filter(parent_level_id=0)
    last_row = org_functional_hierarchy.objects.order_by("-functional_level_id")
    if last_row:
        new_org = org_functional_hierarchy.objects.filter(
            parent_level_id=org[len(org) - 1].functional_level_id
        )
        last_row = org_functional_hierarchy.objects.order_by("-functional_level_id")

        return Response(last_row[0].functional_level_id)
    else:
        return Response(0)


# Insert navigation_menu_details table's data


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_navigation_menu_details(request):
    listData = request.data
    all_items = navigation_menu_details.objects.all()
    for x in range(len(listData)):
        data = {
            "menu_name": listData[x]["menu_name"],
            "parent_menu_id": listData[x]["parent_menu_id"],
            "url": listData[x]["url"],
            "created_by": listData[x]["created_by"],
            "last_updated_by": listData[x]["last_updated_by"],
        }
        check_item = all_items.filter(menu_name=listData[x]["menu_name"])
        serializer = navigation_menu_details_serializer(data=data)
        if serializer.is_valid() and not check_item:
            serializer.save()
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# demo ins


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_user_access(request):
    listData = request.data
    if not listData:
        return Response(
            {"user_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        for x in listData:
            data = {
                "menu_id": listData[x]["menu_id"],
                "user_id": listData[x]["user_id"],
                "add": listData[x]["add"],
                # 'add': {{request.data.get('add')| default_if_none:'Y'}},
                "edit": listData[x]["edit"],
                "view": listData[x]["view"],
                "delete": listData[x]["delete"],
                "created_by": listData[x]["created_by"],
                "last_updated_by": listData[x]["last_updated_by"],
            }
            serializer = user_access_definition_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


# demo Ins user group details
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_group_access(request):
    listData = request.data
    print("REquest Data :",listData)
    if not listData:
        return Response(
            {"group_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        if 'group_name' in dict(listData[list(listData)[0]]):
            data = {
                'name': dict(listData[list(listData)[0]])['group_name']
            }
            group_serializer = auth_group_serializer(data=data)
            if group_serializer.is_valid():
                print("HI")
                group_serializer.save()
                for x in listData:
                    if x != '0' :
                        data = {
                            "menu_id": listData[x]["menu_id"],
                            "group_id": group_serializer.data['id'],
                            "add": listData[x]["add"] if 'add' in listData[x] else 'Y' if listData[x]["menu_id"]==1 or listData[x]["menu_id"]==30 else 'N',
                            "edit": listData[x]["edit"] if 'edit' in listData[x] else 'Y' if listData[x]["menu_id"]==1 or listData[x]["menu_id"]==30 else 'N',
                            "view": listData[x]["view"] if 'view' in listData[x] else 'Y' if listData[x]["menu_id"]==1 or listData[x]["menu_id"]==30 else 'N',
                            "delete": listData[x]["delete"] if 'delete' in listData[x] else 'Y' if listData[x]["menu_id"]==1 or listData[x]["menu_id"]==30 else 'N',
                            "created_by": listData[x]["created_by"],
                            "last_updated_by": listData[x]["last_updated_by"],
                        }
                        serializer = group_access_definition_serializer(data=data)
                        if serializer.is_valid():
                            print("BYE")
                            serializer.save()
                        else:
                            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(group_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # for x in listData:
        #     data = {
        #         "menu_id": listData[x]["menu_id"],
        #         "group_id": listData[x]["group_id"],
        #         "add": listData[x]["add"],
        #         "edit": listData[x]["edit"],
        #         "view": listData[x]["view"],
        #         "delete": listData[x]["delete"],
        #         "created_by": listData[x]["created_by"],
        #         "last_updated_by": listData[x]["last_updated_by"],
        #     }
            # serializer = group_access_definition_serializer(data=data)
            # if serializer.is_valid():
            #     serializer.save()
            # else:
            #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


# View all
# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_navigation_menu_details(request, id=0):
#     if id == 0:
#         org = navigation_menu_details.objects.filter(delete_flag=False)
#     else:
#         org = navigation_menu_details.objects.filter(menu_id=id)

#     serializer = navigation_menu_details_serializer(org, many=True)
#     return Response(serializer.data)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_navigation_menu_details(request, id=0):
    # Fetch data based on delete_flag and order by menu_id
    if id == 0:
        org = navigation_menu_details.objects.filter(delete_flag=False).order_by('menu_id')
    else:
        org = navigation_menu_details.objects.filter(menu_id=id, delete_flag=False).order_by('menu_id')

    # Serialize the data
    serialized_data = navigation_menu_details_serializer(org, many=True).data
    
    # print("Serializer data :",serialized_data)

    # Process the data to group parent -> children
    def sort_menu_hierarchy(data):
        result = []
        menu_dict = {}  # Dictionary to store menus by menu_id

        # Organize data into a dictionary for easy lookup
        for menu in data:
            menu_dict[menu["menu_id"]] = menu

        # Add top-level menus (parent_menu_id == 0) and their children
        for menu in data:
            if menu["parent_menu_id"] == 0:  # Top-level menu
                result.append(menu)
                # Find children with parent_menu_id == current menu_id
                children = [child for child in data if child["parent_menu_id"] == menu["menu_id"]]
                result.extend(children)

        return result

    # Sort the menu hierarchy
    ordered_data = sort_menu_hierarchy(serialized_data)
    # print("Ordered data :",ordered_data)

    # Return the sorted and structured response
    return Response(ordered_data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_single_navigation_menu_details(request, id):
    try:
        data = navigation_menu_details.objects.filter(page_number=id)
        if not data:
            return Response({"message": "Navigation menu not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            serializer = navigation_menu_details_serializer(data, many=True)
            return Response(serializer.data)
    except Exception as e:
        return Response({"message": f"Something went wrong: {str(e)}"},  status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# Insert navigation_menu_details
@api_view(["POST"])
# Insert user_access_definition
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def ins_user_access_definition(request):
#     data = {
#         'menu_id': request.data.get('menu_id'),
#         'user_id': request.data.get('user_id'),
#         'add': request.data.get('add'),
#         'edit': request.data.get('edit'),
#         'view': request.data.get('view'),
#         'delete': request.data.get('delete'),
#         'created_by': request.data.get('created_by'),
#         'last_updated_by': request.data.get('last_updated_by')
#     }
#     serializer = user_access_definition_serializer(data=data)
#     if serializer.is_valid():
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_201_CREATED)
#     else:
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# Insert user_access_definition
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_user_access_definition(self, request, id, format=None):
    listData = request.data
    if not listData:
        return Response(
            {"user_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        for x in listData:
            data = {
                "menu_id": listData[x]["menu_id"],
                "user_id": listData[x]["user_id"],
                "add": listData[x]["add"],
                # 'add': {{request.data.get('add')| default_if_none:'Y'}},
                "edit": listData[x]["edit"],
                "view": listData[x]["view"],
                "delete": listData[x]["delete"],
                "created_by": listData[x]["created_by"],
                "last_updated_by": listData[x]["last_updated_by"],
            }
            serializer = user_access_definition_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.data, status=status.HTTP_201_CREATED)


# update user access defintion


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_user_access_definition(request, id):
    listData = request.data
    if not listData:
        return Response(
            {"user_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        all_item = user_access_definition.objects.all()
        for x in listData:
            data = {
                "menu_id": listData[x]["menu_id"],
                "user_id": listData[x]["user_id"],
                "add": listData[x]["add"],
                # 'add': {{request.data.get('add')| default_if_none:'Y'}},
                "edit": listData[x]["edit"],
                "view": listData[x]["view"],
                "delete": listData[x]["delete"],
                "created_by": listData[x]["created_by"],
                "last_updated_by": listData[x]["last_updated_by"],
            }

            selected_item = all_item.filter(
                menu_id=listData[x]["menu_id"], user_id=id
            ).first()
            if not selected_item:
                serializer = user_access_definition_serializer(data=data)
                if serializer.is_valid():
                    serializer.save()
            else:
                serializer = user_access_definition_serializer(
                    instance=selected_item, data=data
                )
                if serializer.is_valid():
                    serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


# ins group access definition
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_group_access_definition(self, request, id, format=None):
    listData = request.data
    if not listData:
        return Response(
            {"group_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        for x in listData:
            data = {
                "menu_id": listData[x]["menu_id"],
                "group_id": listData[x]["group_id"],
                "add": listData[x]["add"],
                # 'add': {{request.data.get('add')| default_if_none:'Y'}},
                "edit": listData[x]["edit"],
                "view": listData[x]["view"],
                "delete": listData[x]["delete"],
                "created_by": listData[x]["created_by"],
                "last_updated_by": listData[x]["last_updated_by"],
            }
            serializer = group_access_definition_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response(serializer.data, status=status.HTTP_201_CREATED)


# upd group access definition


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_group_access_definition(request, id):
    listData = request.data
    if not listData:
        return Response(
            {"user_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        all_item = group_access_definition.objects.all()
        for x in listData:
            data = {
                "menu_id": listData[x]["menu_id"],
                "group_id": listData[x]["group_id"],
                "add": listData[x]["add"],
                # 'add': {{request.data.get('add')| default_if_none:'Y'}},
                "edit": listData[x]["edit"],
                "view": listData[x]["view"],
                "delete": listData[x]["delete"],
                "created_by": listData[x]["created_by"],
                "last_updated_by": listData[x]["last_updated_by"],
            }

            selected_item = all_item.filter(
                menu_id=listData[x]["menu_id"], group_id=id
            ).first()
            if not selected_item:
                serializer = group_access_definition_serializer(data=data)
                if serializer.is_valid():
                    serializer.save()
            else:
                serializer = group_access_definition_serializer(
                    instance=selected_item, data=data
                )
                if serializer.is_valid():
                    serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)

# User


# View all
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_user_details(request):
    org = User.objects.filter(is_active="1")
    serializer = user_serializer(org, many=True)
    return Response(serializer.data)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_details_with_profile(request):
    # Fetch all active users
    users = User.objects.filter(is_active="1")
    # Serialize user data
    users_serializer = user_serializer(users, many=True)
    # Get all profiles
    profiles = user_profile.objects.filter(user_id__in=[user.id for user in users])
    # Serialize profile data
    profile_serializer = user_profile_serializer(profiles, many=True)
    
    # Convert profile data into a dictionary for quick lookup
    profile_data_dict = {profile["user_id"]: profile for profile in profile_serializer.data}
    
    # Merge user data with their respective profile data
    combined_data = []
    for user in users_serializer.data:
        profile_data = profile_data_dict.get(user["id"], {})  # Get profile data or default to {}

        if (profile_data["delete_flag"] == False):
            combined_data.append({**user, **profile_data})  # Merge user and profile data
    
    return Response(combined_data, status=status.HTTP_200_OK)

# View particular user
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_Prticular_user_details(request, id=0):
    if id == 0:
        UserObj = User.objects.filter(is_active="1")
        serializer = user_serializer(UserObj, many=True)
        return Response(serializer.data)
    else:
        UserObj = User.objects.filter(id=id)
        serializer = user_serializer(UserObj, many=True)
        return Response(serializer.data)



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_user_details_with_profile(request, start, end, search=False):
    try:
        # Fetch users based on search
        query = User.objects.filter(is_active="1")
        if search:
            query = query.filter(
                Q(username__icontains=search) 
            )

        # Get user profiles
        profiles = user_profile.objects.filter(user_id__in=[qry.id for qry in query])
        profile_serializer = user_profile_serializer(profiles, many=True)

        # Convert profile data into a dictionary for quick lookup
        profile_data_dict = {profile["user_id"]: profile for profile in profile_serializer.data}

        # Serialize user data
        users_serializer = user_serializer(query, many=True)

        # Merge user data with their respective profile data
        combined_data = []
        for user in users_serializer.data:
            profile_data = profile_data_dict.get(user["id"], {})

            if not profile_data.get("delete_flag", True):
                combined_data.append({**user, **profile_data})

        # Count total records
        users_length = len(combined_data)

        # Slice data for pagination
        dummyData = combined_data[start:end]
        
        return Response(
            {
                "data": dummyData,
                "data_length": users_length,
            }, status=status.HTTP_200_OK
        )

    except Exception as e:
        print("ERROR:", e)
        return Response(str(e), status=status.HTTP_400_BAD_REQUEST)
    
    
# To get Details about Logged in User
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_logged_in_user(request, id=0):
    if id == 0:
        tb_sc_profile_data = user_profile.objects.filter(delete_flag="N")
        tb_sc_auth_user_data = User.objects.filter(is_active="1")
    else:
        tb_sc_profile_data = user_profile.objects.filter(user_id=id)
        tb_sc_auth_user_data = User.objects.filter(id=id)
        
    profile_serializer = user_profile_serializer(tb_sc_profile_data, many=True)
    auth_user_serializer = user_serializer(tb_sc_auth_user_data, many=True)
    
    # Merge the first items of both serializers if data exists
    profile_data = profile_serializer.data[0] if profile_serializer.data else {}
    auth_user_data = auth_user_serializer.data[0] if auth_user_serializer.data else {}
    
    # Combine data
    combined_data = {**profile_data, **auth_user_data}
    
    return Response(combined_data, status=status.HTTP_200_OK)

# Join user and user_access_definition table view
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_user_access(request, id, menu_id=0):
    if menu_id == 0:
        reports = user_access_definition.objects.select_related("user_id").filter(
            user_id=id
        )
    else:
        reports = user_access_definition.objects.select_related(
            "user_id", "menu_id"
        ).filter(user_id=id, menu_id=menu_id)
    data = user_user_access_serializer(
        reports, many=True, context={"request": request}
    ).data
    return Response(data, status=status.HTTP_200_OK)


# Join group and group_access_definition table view
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def group_group_access(request, id=0, menu_id=0):
    if id == 0:
        org = navigation_menu_details.objects.filter(delete_flag=False)
        serializer = navigation_menu_details_serializer(org, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        if menu_id == 0:
            reports = group_access_definition.objects.select_related("group_id").filter(group_id=id)
        else:
            superadmin = User.objects.filter(id=id).values('is_superuser')
            grp_id = ConvertQuerysetToJson(User.objects.get(id=id).groups.all())
            if superadmin[0]['is_superuser']:
                reports = group_access_definition.objects.select_related(
                    "group_id", "menu_id"
                ).filter(group_id=1, menu_id=menu_id)
            else:
                reports = group_access_definition.objects.select_related(
                "group_id", "menu_id"
                ).filter(group_id=grp_id["id"], menu_id=menu_id)
            # reports = group_access_definition.objects.select_related("group_id").filter(group_id=id, menu_id=menu_id)
        data = group_group_access_serializer(
            reports, many=True, context={"request": request}
        ).data
        return Response(data, status=status.HTTP_200_OK)


# Join group and group_access_definition table view
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def group_group_access(request, id=0, menu_id=0):
    if id == 0:
        org = navigation_menu_details.objects.filter(delete_flag=False)
        serializer = navigation_menu_details_serializer(org, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        if menu_id == 0:
            reports = group_access_definition.objects.select_related("group_id").filter(group_id=id)
        else:
            superadmin = User.objects.filter(id=id).values('is_superuser')
            grp_id = ConvertQuerysetToJson(User.objects.get(id=id).groups.all())
            if superadmin[0]['is_superuser']:
                reports = group_access_definition.objects.select_related(
                    "group_id", "menu_id"
                ).filter(group_id=1, menu_id=menu_id)
            else:
                reports = group_access_definition.objects.select_related(
                "group_id", "menu_id"
                ).filter(group_id=grp_id["id"], menu_id=menu_id)
            # reports = group_access_definition.objects.select_related("group_id").filter(group_id=id, menu_id=menu_id)
        data = group_group_access_serializer(
            reports, many=True, context={"request": request}
        ).data
        return Response(data, status=status.HTTP_200_OK)
    
# Get User Access Definition Table

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_access_definition(request, id=0):
    if id == 0:
        org = user_access_definition.objects.filter(delete_flag=False)
    else:
        org = user_access_definition.objects.filter(user_id=id)

    serializer = user_access_definition_serializer(org, many=True)
    return Response(serializer.data)


# get group access definition


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_group_access_definition(request, id=0):
    if id == 0:
        org = group_access_definition.objects.filter(delete_flag=False)
    else:
        org = group_access_definition.objects.filter(group_id=id)

    serializer = group_access_definition_serializer(org, many=True)
    return Response(serializer.data)


# --Chart Attributes Settings---

# GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_chart_attributes_settings(
    request, id=0, chart_type="", component="", attr_name=""
):
    if id == 0 and chart_type == "":
        attr = chart_attributes.objects.filter(user_id=-1)
    if chart_type != "":
        attr = chart_attributes.objects.filter(chart_type=chart_type, user_id=-1)

    if component:
        attr = chart_attributes.objects.filter(
            chart_type=chart_type, component=component, user_id=-1
        )
    if attr_name:
        attr = chart_attributes.objects.filter(
            chart_type=chart_type, component=component, attr_name=attr_name, user_id=-1
        )
    serializer = chart_attributes_serializer(attr, many=True)
    return Response(serializer.data)


# UPDATE


@api_view(["PUT"])
# @permission_classes([IsAuthenticated])
def upd_chart_attributes_settings(request, id):
    updated_attributes = []
    listdata = request.data[0]
    listKeys = ["user_id", "chart_type", "component", "Margin", "Gauge"]

    for key in listdata:
        if key == "Margin":
            for marginData in listdata[key]:
                chart_attributes.objects.filter(id=marginData["id"]).update(
                    attr_value=marginData["attr_value"]
                )
        
        if key == "Gauge":
            for marginData in listdata[key]:
                chart_attributes.objects.filter(id=marginData["id"]).update(
                    attr_value=marginData["attr_value"]
                )

        if key not in listKeys:
            AtrributeList = listdata[key]
            for KeyOfkey in AtrributeList:
                for value in AtrributeList[KeyOfkey]:
                    chart_attributes.objects.filter(id=value["id"]).update(
                        attr_value=value["attr_value"]
                    )

    return Response(updated_attributes, status=status.HTTP_200_OK)


# --Chart Attributes---

# GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_chart_attributes(request, id=0, chart_type=""):
    if id == 0:
        attr = chart_attributes.objects.filter(chart_type=chart_type, user_id=-1)
    else:
        attr = chart_attributes.objects.filter(user_id=id, chart_type=chart_type)
    serializer = chart_attributes_serializer(attr, many=True)
    return Response(serializer.data)


# ADD


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_chart_attributes(request):
    data = {
        "user_id": request.data.get("user_id"),
        "chart_type": request.data.get("chart_type"),
        "component": request.data.get("component"),
        "attr_name": request.data.get("attr_name"),
        "attr_key": request.data.get("attr_key"),
        "attr_value": request.data.get("attr_value"),
    }
    serializer = chart_attributes_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# UPDATE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_chart_attributes(request, id):
    item = chart_attributes.objects.get(id=id)
    
    serializer = chart_attributes_serializer(instance=item, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


# DELETE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_chart_attributes(request, id):
    item = chart_attributes.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = chart_attributes_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

# Chart Attributes Options

# GET

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_chart_attributes_options(request, id=0):
    if id == 0:
        chart_options = chart_attributes_options.objects.filter(delete_flag=False)
    else:
        chart_options = chart_attributes_options.objects.filter(id=id)

    serializer = chart_attributes_options_serializer(chart_options, many=True)
    return Response(serializer.data)

# FOR Configs Codes

# class search_config_type(generics.ListAPIView):
#     queryset = config_codes.objects.filter(delete_flag=False)
#     serializer_class = config_codes_serializer
#     filter_backends = [filters.SearchFilter]
#     search_fields = ["$config_type"]


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def multifilterconfigtype(request, config_type):
#     currencies_dual = config_codes.objects.all()
#     ccode = config_type.split(",")
#     currencies_dual = config_codes.objects.filter(config_type__in=ccode)
#     serializer = config_codes_serializer(currencies_dual, many=True)
#     return Response(serializer.data)

# Config Codes

# GET Range
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_config_codes(request, start, end, search=False):
    try:
        if not search:
            config_len = config_codes.objects.filter(delete_flag=False, is_admindata=False).count()
            config = config_codes.objects.filter(~Q(config_type = "Measure"), delete_flag=False, is_admindata=False)[start:end]
        else:
            config_len = config_codes.objects.filter(Q(config_type__icontains = search) | Q(config_code__icontains = search) | Q(config_value__icontains = search), delete_flag=False).count()
            config = config_codes.objects.filter(Q(config_type__icontains = search) | Q(config_code__icontains = search) | Q(config_value__icontains = search), delete_flag=False)[start:end]
        config_csv_export = config_codes.objects.filter(delete_flag=False, is_admindata=False)
        serializer = config_codes_serializer(config, many=True)
        serializer_csv_export = config_codes_serializer(config_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": config_len,
                "csv_data": serializer_csv_export.data,
            }
        )
    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)

# Get By ID
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_config_codes(request, value=''):
    if value == '':
        config = config_codes.objects.filter(delete_flag=False)
    else:
        config = config_codes.objects.filter(config_type=value, delete_flag=False, is_active=True)
    serializer = config_codes_serializer(config, many=True)
    return Response(serializer.data)


# Get regions from config table
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_config_details(request, search=''):
    if search !='':
        config = config_codes.objects.filter(config_type = search, delete_flag=False, is_active=True, is_admindata=False)
    else:
        config = config_codes.objects.filter(delete_flag=False, is_admindata=False)
    serializer = config_codes_serializer(config, many=True)
    return Response(serializer.data)

# ADD
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_config_codes(request):
    data = {
        "config_type": request.data.get("config_type"),
        "config_code": request.data.get("config_code"),
        "config_value": request.data.get("config_value"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
        "is_active": False
        if request.data.get("is_active") == None
        else request.data.get("is_active"),
    }
    serializer = config_codes_serializer(data=data)
    
    all_serializer_fields = list(serializer.fields.keys())

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]


    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        e_code = []
        e_msg = []
        e_field = []
        # Iterate over each field's errors
        for field, error_list in error_data.items():
            for error_data in error_list:
                # Access the error code
                error_code = error_data.code
                e_code.append(error_code)
                e_msg.append(error_data)
                e_field.append(field)

        # index_to_replace = e_field.index('non_field_errors')

        # Replace 'non_field_errors' with 'config_codes'
        # e_field[index_to_replace] = 'config_code'
        
        # Remove the excluded fields from the list of field names
        non_e_field = [for_field for for_field in required_serializer_fields if for_field not in e_field]


        data_warning = warnings.objects.filter(
            error_code__in=e_code, error_from="Server"
        )
        serializer_warning = warnings_serializer(data_warning, many=True)
        # print("serializer_warning length", serializer_warning.data)

        # ! test validation on Backend level

        field_arr = []
        for iter in range(len(e_code)):
            for j in serializer_warning.data:
                # print("out : ", e_code[iter], j["error_code"])
                if e_code[iter] == j["error_code"]:
                    field_arr.append(
                        (j["error_msg"]).replace("%1", e_field[iter].replace("_", " "))
                    )
                    # print("true")
                    # print("j:", j["error_msg"])
                else:
                    print("i:", e_code[iter])

        # print("field_arr", field_arr)

        data = []
        for i in range(len(e_code)):
            # print(f"Error code for field '{field}': {error_code}")
            data.append({e_field[i]: [field_arr[i]]})
        # print("data", data)

        for i in range(len(non_e_field)):
            data.append({non_e_field[i]: ''})
        # print("data", data)

        def order_data(data):
            # Define the desired field order
            field_order = {
                'config_type': 0,
                'config_code': 1,
                'config_value': 2,
            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)


# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_config_codes(request, id):
    item = config_codes.objects.get(id=id, is_admindata=False)

    serializer = config_codes_serializer(instance=item, data=request.data)
    
    all_serializer_fields = list(serializer.fields.keys())

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        e_code = []
        e_msg = []
        e_field = []
        # Iterate over each field's errors
        for field, error_list in error_data.items():
            for error_data in error_list:
                # Access the error code
                error_code = error_data.code
                e_code.append(error_code)
                e_msg.append(error_data)
                e_field.append(field)

        # Remove the excluded fields from the list of field names
        non_e_field = [for_field for for_field in required_serializer_fields if for_field not in e_field]

        # print("non_e_field",non_e_field)

        data_warning = warnings.objects.filter(
            error_code__in=e_code, error_from="Server"
        )
        serializer_warning = warnings_serializer(data_warning, many=True)
        # print("serializer_warning length", serializer_warning.data)

        # ! test validation on Backend level

        field_arr = []
        for iter in range(len(e_code)):
            for j in serializer_warning.data:
                # print("out : ", e_code[iter], j["error_code"])
                if e_code[iter] == j["error_code"]:
                    field_arr.append(
                        (j["error_msg"]).replace("%1", e_field[iter].replace("_", " "))
                    )
                    # print("true")
                    # print("j:", j["error_msg"])
                else:
                    print("i:", e_code[iter])

        # print("field_arr", field_arr)

        data = []
        for i in range(len(e_code)):
            # print(f"Error code for field '{field}': {error_code}")
            data.append({e_field[i]: [field_arr[i]]})
        # print("data", data)

        for i in range(len(non_e_field)):
            data.append({non_e_field[i]: ''})
        # print("data", data)

        def order_data(data):
            # Define the desired field order
            field_order = {
                'config_type': 0,
                'config_code': 1,
                'config_value': 2,
            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data
        # print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)

# DELETE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_config_codes(request, id):
    item = config_codes.objects.get(id=id, is_admindata=False)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = config_codes_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# ----settings---- #
# Get
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_settings(request, id=0):
    if id == 0:
        pers = settings.objects.filter(delete_flag=False)
    else:
        pers = settings.objects.filter(user_id=id)
    serializer = settings_serializer(pers, many=True)
    return Response(serializer.data)


# Put and insert
# @api_view(["PUT"])
# @permission_classes([IsAuthenticated])
# def upd_settings(request, id):
#     listData = request.data
#     print("lisdtData :",listData)
#     if not listData:
#         return Response(
#             {"user_id": "This field is may not be empty"},
#             status=status.HTTP_400_BAD_REQUEST,
#         )
#     else:
#         all_item = settings.objects.all()
#         for x in listData:
#             if 'value' in listData[x] and listData[x]["value"] != '':
#                 data = {
#                     "variable_name": listData[x]["variable_name"],
#                     "value": listData[x]["value"],
#                     "types": listData[x]["types"] if "types" in listData[x] else '',
#                     "hours": int(listData[x]["hours"]) if "hours" in listData[x] else '12',
#                     "seconds": int(listData[x]["seconds"]) if "seconds" in listData[x] else '00',
#                     "ampm": listData[x]["ampm"] if "ampm" in listData[x] else 'am',
#                     "user_id": id,
#                     "created_by": listData[x]["created_by"],
#                     "last_updated_by": listData[x]["last_updated_by"],
#                 }
#                 selected_item = all_item.filter(
#                     variable_name=listData[x]["variable_name"], user_id=id
#                 ).first()
#                 if not selected_item:
#                     serializer = settings_serializer(data=data)
#                     if serializer.is_valid():
#                         serializer.save()
#                     else:
#                         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#                 else:
#                     serializer = settings_serializer(instance=selected_item, data=data)
#                     if serializer.is_valid():
#                         serializer.save()
#                     else:
#                         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#         updater.jobs_scheduler(id=id)
#         return Response("Success", status=status.HTTP_200_OK)

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_settings(request, id):
    listData = request.data.get("inputs")
    if not listData:
        return Response(
            {"user_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        org_settings_view = settings.objects.filter(variable_name="Logo").first()
    
        if(org_settings_view):
            if len(org_settings_view.logo) > 0 and org_settings_view.logo != request.data.get("value"):
                os.remove(org_settings_view.logo.path)
                
            if org_settings_view.logo != request.data.get("value"):
                org_settings_view.logo = request.data.get("value")
            if org_settings_view.created_by != request.data.get("created_by"):
                org_settings_view.created_by = request.data.get("created_by")
            if org_settings_view.last_updated_by != request.data.get("last_updated_by"):
                org_settings_view.last_updated_by = request.data.get("last_updated_by")
                
            org_settings_view.save()
            
        else:
            data = {
                "variable_name": request.data.get("variable_name"),
                "value": "logo path",
                "user_id": request.data.get("user_id"),
                "created_by": request.data.get("created_by"),
                "last_updated_by": request.data.get("last_updated_by"),
                "logo": request.data.get("value"),        
            }
            
            serializer = settings_serializer(data=data)
            if serializer.is_valid():
                logo_instance = serializer.save()
            else:
                print("Error's :",serializer.errors)

        if isinstance(listData, str):  # If it's a string, parse it
            try:
                listData = json.loads(listData)
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON format"}, status=status.HTTP_400_BAD_REQUEST)

        all_item = settings.objects.all()
        for key, value in listData.items():
            if isinstance(value, dict) and 'value' in value and value["value"] != '':
                data = {
                    "variable_name": value["variable_name"],
                    "value": value["value"],
                    "types": value.get("types", ''),
                    "hours": int(value["hours"]) if "hours" in value and value["hours"] is not None else 12,
                    "seconds": int(value["seconds"]) if "seconds" in value and value["seconds"] is not None else 0,
                    "ampm": value.get("ampm", 'am'),
                    "user_id": id,
                    "created_by": value["created_by"],
                    "last_updated_by": value["last_updated_by"],
                }
                
                selected_item = all_item.filter(variable_name=value["variable_name"], user_id=id).first()
                
                if not selected_item:
                    serializer = settings_serializer(data=data)
                    if serializer.is_valid():
                        serializer.save()
                    else:
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                else:
                    serializer = settings_serializer(instance=selected_item, data=data)
                    if serializer.is_valid():
                        serializer.save()
                    else:
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # updater.jobs_scheduler(id=id)
        return Response("Success", status=status.HTTP_200_OK)

    
# Global Validation Error Message api's

# GET

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_warnings(request, id=0):
    if id == 0:
        get_warning_data = warnings.objects.all()
    else:
        get_warning_data = warnings.objects.filter(id=id)

    serializer = warnings_serializer(get_warning_data, many=True)
    return Response(serializer.data)

# Global helper api's

# GET

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_helper(request, id=0):
    if id == 0:
        chart_options = helper.objects.all()
    else:
        chart_options = helper.objects.filter(page_no=id)

    serializer = helper_serializer(chart_options, many=True)
    return Response(serializer.data)

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_countries(request, id=0):
    if id == 0:
        country = countries.objects.filter(delete_flag=False)
    else:
        country = countries.objects.filter(id=id)

    serializer = countries_serializer(country, many=True)
    return Response(serializer.data)

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_state(request, id=0):
    state_data = states.objects.filter(country_id=id)
    serializer = state_serializer(state_data, many=True)
    return Response(serializer.data)


# get compliance details
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_compliance_details(request, start, end, search=False):
    try:
        if not search:
            details_lengrth = compliance_details.objects.filter(delete_flag=False).count()
            details = compliance_details.objects.filter(delete_flag=False)[start:end]
        else:
            details_lengrth = compliance_details.objects.filter(delete_flag=False).count()
            details = compliance_details.objects.filter(Q(compliance_group_name__icontains = search) | Q(compliance_name__icontains = search) | Q(compliance_criteria__icontains = search) | Q(compliance_value__icontains = search) | Q(value_type__icontains = search) | Q(option_type__icontains = search) | Q(effective_from__icontains = search), delete_flag=False)[start:end]
        serializer = compliance_details_serializer(details, many=True)
        details_csv_export = compliance_details.objects.filter(delete_flag=False)
        serializer_csv_export = compliance_details_serializer(details_csv_export, many=True)
        
        compliance_data = serializer.data
        
        if len(serializer.data) > 0:
            for data in serializer.data:
                if(data['value_type']=='Options'):
                    # Compliance Code to Value
                    compliance_code = compliance_codes.objects.filter(id=int(data['compliance_value']), delete_flag=False).first()
                    if compliance_code:
                        data['compliance_values'] = compliance_code.compliance_value
                else:
                    data['compliance_values'] = data['compliance_value']
        
        if len(serializer_csv_export.data) > 0:
            for data in serializer_csv_export.data:
                if(data['value_type']=='Options'):
                    # Compliance Code to Value
                    compliance_code = compliance_codes.objects.filter(id=int(data['compliance_value']), delete_flag=False).first()
                    if compliance_code:
                        data['compliance_values'] = compliance_code.compliance_value
                else:
                    data['compliance_values'] = data['compliance_value']
                
        return Response(
            {
                "data": serializer.data,
                "data_length": details_lengrth,
                "csv_data": serializer_csv_export.data,
            }, status=status.HTTP_200_OK
        )
    except Exception as e:
        print("ERROR :",e)
        return Response(e, status=status.HTTP_400_BAD_REQUEST)
    
# @api_view(["GET"])
# # @permission_classes([IsAuthenticated])
# def get_range_compliance_codes(request, start, end, search=False):
#     try:
#         if not search:
#             compliance_len = compliance_codes.objects.filter(delete_flag=False).count()
#             compliance = compliance_codes.objects.filter( delete_flag=False)[start:end]
#         else:
#             compliance_len = compliance_codes.objects.filter(Q(compliance_type__icontains = search) | Q(compliance_code__icontains = search) | Q(compliance_value__icontains = search), delete_flag=False).count()
#             compliance = compliance_codes.objects.filter(Q(compliance_type__icontains = search) | Q(compliance_code__icontains = search) | Q(compliance_value__icontains = search), delete_flag=False)[start:end]
#         compliance_csv_export = compliance_codes.objects.filter(delete_flag=False)
#         serializer = compliance_codes_serializer(compliance, many=True)
#         compliance_data = serializer.data
        
#         # Serializer for CSV data (all records)
#         compliance_csv_export = compliance_codes.objects.filter(delete_flag=False)
#         serializer_csv_export = compliance_codes_serializer(compliance_csv_export, many=True)
#         csv_data = serializer_csv_export.data

#         # Mapping to keep track of compliance_code "0" values for header lookup
#         compliance_code_map = {item["compliance_code"]: item["compliance_value"] for item in csv_data}
#         print("compliance_code_map :",compliance_code_map)

#         # Add compliance_header to each item in compliance_data
#         for item in compliance_data:
#             compliance_code = item.get("compliance_code")
#             print("compliance_code:", compliance_code)
            
#             if compliance_code == "0":
#                 item["compliance_header"] = "--Header--"
#             else:
#                 # Retrieve the compliance value using the compliance_code
#                 head_value = compliance_codes.objects.filter(id=compliance_code, delete_flag=False).first()
#                 if head_value:
#                     item["compliance_header"] = head_value.compliance_value

#         return Response(
#             {
#                 "data": compliance_data,
#                 "data_length": compliance_len,
#                 "csv_data": csv_data,
#             },
#             status=status.HTTP_200_OK
#         )

#     except Exception as e:
#         print("ERROR :",e)
#         return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# insert compliance details
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_compliance_details(request):
    data = {
        "compliance_group_name": request.data.get("compliance_group_name"),
        "compliance_name": request.data.get("compliance_name"),
        "compliance_criteria": request.data.get("compliance_criteria"),
        "compliance_value": request.data.get("compliance_value"),
        "value_type": request.data.get("value_type"),
        "option_type": request.data.get("option_type"),
        "effective_from": request.data.get("effective_from"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by")
    }
    
    serializer = compliance_details_serializer(data=data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

# Compliance Rules Insert single and multi record 
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@transaction.atomic
def ins_compliance_details_bulk(request):
    insertData = request.data
    successful_inserts = []
    errors = []
    try:

        # Process each item in the input data list
        for item in insertData:
            data = {
                "compliance_group_name": item.get("compliance_group_name"),
                "compliance_name": item.get("compliance_name"),
                "compliance_criteria": item.get("compliance_criteria"),
                "compliance_value": item.get("compliance_value"),
                "value_type": item.get("value_type"),
                "option_type": item.get("option_type", "nill"),
                "created_by": item.get("created_by"),
                "last_updated_by": item.get("last_updated_by"),
            }

            serializer = compliance_details_serializer(data=data)
            
            all_serializer_fields = list(serializer.fields.keys())
            # Check if the serializer data is valid
            fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date', 'option_type']
            required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

            # Check if the serializer data is valid
            if serializer.is_valid():
                serializer.save()
                successful_inserts.append(serializer.data)
            else:
                error_data = serializer.errors
                print("SER ERRORS :",error_data)
                e_code, e_msg, e_field = [], [], []

                # Collect error details for each field
                for field, error_list in error_data.items():
                    for error_detail in error_list:
                        error_code = error_detail.code
                        e_code.append(error_code)
                        e_msg.append(error_detail)
                        e_field.append(field)

                # Fetch custom error messages based on error codes
                non_e_field = [field for field in required_serializer_fields if field not in e_field]
                data_warning = warnings.objects.filter(error_code__in=e_code, error_from="Server")
                serializer_warning = warnings_serializer(data_warning, many=True)
                
                field_arr = []
                for idx, code in enumerate(e_code):
                    for warning in serializer_warning.data:
                        if code == warning["error_code"]:
                            field_arr.append(warning["error_msg"].replace("%1", e_field[idx].replace("_", " ")))

                data = [{e_field[i]: [field_arr[i]]} for i in range(len(e_code))]
                data += [{field: ''} for field in non_e_field]

                def order_data(data):
                    field_order = {
                        'compliance_group_name': 0,
                        'compliance_name': 1,
                        'compliance_criteria': 2,
                        'value_type': 3,
                        'compliance_value': 4
                    }
                    return sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

                ordered_data = order_data(data)
                errors.append({"record": item, "errors": ordered_data})

        if errors:
            return Response(ordered_data, status=status.HTTP_400_BAD_REQUEST)
        return Response(successful_inserts, status=status.HTTP_200_OK)

    except Exception as e:
        transaction.set_rollback(True)
        print("ERROR :", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# update compliance details
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_compliance_details(request, id):
    item = compliance_details.objects.get(id=id)
    serializer = compliance_details_serializer(instance=item, data=request.data)

    all_serializer_fields = list(serializer.fields.keys())
    

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]


    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        e_code = []
        e_msg = []
        e_field = []
        # Iterate over each field's errors
        for field, error_list in error_data.items():
            for error_data in error_list:
                # Access the error code
                error_code = error_data.code
                e_code.append(error_code)
                e_msg.append(error_data)
                e_field.append(field)

        # print("e_code", e_code, "length", len(e_code))
        # print("e_msg", e_msg, "length", len(e_msg))
        # print("e_field", e_field, "length", len(e_field))

        # Remove the excluded fields from the list of field names
        non_e_field = [for_field for for_field in required_serializer_fields if for_field not in e_field]

        # print("non_e_field",non_e_field)

        data_warning = warnings.objects.filter(
            error_code__in=e_code, error_from="Server"
        )
        serializer_warning = warnings_serializer(data_warning, many=True)
        # print("serializer_warning length", serializer_warning.data)

        # ! test validation on Backend level

        field_arr = []
        for iter in range(len(e_code)):
            for j in serializer_warning.data:
                # print("out : ", e_code[iter], j["error_code"])
                if e_code[iter] == j["error_code"]:
                    field_arr.append(
                        (j["error_msg"]).replace("%1", e_field[iter].replace("_", " "))
                    )
                    # print("true")
                    # print("j:", j["error_msg"])
                else:
                    print("false")
                    print("i:", e_code[iter])

        # print("field_arr", field_arr)

        data = []
        for i in range(len(e_code)):
            # print(f"Error code for field '{field}': {error_code}")
            data.append({e_field[i]: [field_arr[i]]})
        # print("data", data)

        for i in range(len(non_e_field)):
            data.append({non_e_field[i]: ''})
        # print("data", data)

        def order_data(data):
            # Define the desired field order
            field_order = {
                'compliance_group_name': 0,
                'compliance_name': 1,
                'compliance_criteria': 2,
                'value_type': 3,
                'option_type': 4,
                'compliance_value': 5,            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data
        # print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)


# Delete compliance details
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_compliance_details(request, id):
    item = compliance_details.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = compliance_details_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

# CounterParty Details

import operator
import math

ops = {
    '==': operator.eq,
    '!=': operator.ne,
    '>=': operator.ge,
    '<=': operator.le,
    '>': operator.gt,
    '<': operator.lt,
}

def evaluate_condition(left_value, right_value, cond_str):
    for op_str in sorted(ops, key=len, reverse=True):  # Match longest operator first
        if op_str in cond_str:
            # left, right = map(str.strip, cond_str.split(op_str))
            return ops[op_str](int(left_value), int(right_value))
    raise ValueError("Unsupported operator")

def evaluate_string_condition(left_value, right_value, cond_str):
    for op_str in sorted(ops, key=len, reverse=True):  # Match longest operator first
        if op_str in cond_str:
            # left, right = map(str.strip, cond_str.split(op_str))
            return ops[op_str](str(left_value), str(right_value))
    raise ValueError("Unsupported operator")


# Get Range CounterParty Details
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_range_counterparty_details(request, start, end, region):
    try:
        if region !='all':
            details_length = counterparty_details.objects.filter(delete_flag=False, plant__region=region).count() #region_id=region,
            details = counterparty_details.objects.filter(delete_flag=False, plant__region=region)[start:end] # region_id=region, 
        else:
            details_length = counterparty_details.objects.filter(delete_flag=False).count()
            details = counterparty_details.objects.filter(delete_flag=False)[start:end]
        serializer = counterparty_details_serializer(details, many=True)
        if len(serializer.data) > 0:
            for data in serializer.data:
                actuals = compliance_actuals.objects.filter(counterparty_id=data['id'], delete_flag=False)
                actuals_serializer = compliance_actuals_serializer(actuals, many=True)
                data['actuals'] = actuals_serializer.data
                # Plant
                plant = plant_details.objects.filter(id=data['plant'], delete_flag=False).first()
                if plant:
                    data['plant_code'] = plant.name  # Extract only the 'name' field
                else:
                    data['plant_code'] = None  # or any default value
                # CounterParty
                party = counterparty_profile.objects.filter(id=data['party_name'], delete_flag=False).first()
                if party:
                    data['party_code'] = party.name  # Extract only the 'name' field
                else:
                    data['party_code'] = None  # or any default value
                    
                if len(data['actuals']) > 0:
                    failed_actuals = 0
                    total_actuals = len(data['actuals'])
                    for detail in data['actuals']:
                        compliance_data = compliance_details.objects.filter(
                            id=detail['compliance_id'], delete_flag=False
                        ).values(
                            'compliance_group_name',
                            'compliance_name',
                            'compliance_value',
                            'compliance_criteria',
                            'effective_from',
                            'option_type',
                            'value_type'
                        ).first()
                        
                        if compliance_data:
                            if(compliance_data['value_type']=='Options'):
                                compliance_code = compliance_codes.objects.filter(id=int(compliance_data['compliance_value']), delete_flag=False).first()
                                if compliance_code:
                                        compliance_data['compliance_values'] = compliance_code.compliance_value
                            else:
                                compliance_data['compliance_values'] = compliance_data['compliance_value']
                            detail.update(compliance_data)
                            
                            if(compliance_data['compliance_criteria']):
                                config_code_details = config_codes.objects.filter(config_type = 'Compliance Criteria', config_value = compliance_data['compliance_criteria'], delete_flag=False).values('config_code')[0]
                                compliance_data['criteria_name'] = config_code_details['config_code']
                            detail.update(compliance_data)
                    for compute_actual in data['actuals']:
                        if compute_actual['actuals'] != '':
                            if compute_actual['value_type'] == 'Number':
                                if not evaluate_condition(compute_actual['actuals'],  compute_actual['compliance_values'], compute_actual['compliance_criteria']):
                                    failed_actuals = failed_actuals+1
                            elif compute_actual['value_type'] == 'Options':
                                if not evaluate_string_condition(compute_actual['actuals'],compute_actual['compliance_value'],compute_actual['compliance_criteria']):
                                    failed_actuals = failed_actuals+1
                            else:
                                if not evaluate_string_condition(compute_actual['actuals'],compute_actual['compliance_value'],compute_actual['compliance_criteria']):
                                    failed_actuals = failed_actuals+1
                        else:
                            failed_actuals = failed_actuals+1
                    print(total_actuals, failed_actuals)
                    data['status'] = str(round(100 - (failed_actuals / total_actuals * 100))) + '%'       
                            
        if region !='all':
            details_csv_export = counterparty_details.objects.filter(delete_flag=False, plant__region=region) #region_id=region,
        else:
            details_csv_export = counterparty_details.objects.filter(delete_flag=False)           
        serializer_csv_export = counterparty_details_serializer(details_csv_export, many=True)
        if len(serializer_csv_export.data) > 0:
            for data in serializer_csv_export.data:
                actuals = compliance_actuals.objects.filter(counterparty_id=data['id'], delete_flag=False)
                actuals_serializer = compliance_actuals_serializer(actuals, many=True)
                data['actuals'] = actuals_serializer.data
                # Plant
                plant = plant_details.objects.filter(id=data['plant'], delete_flag=False).first()
                if plant:
                    data['plant_code'] = plant.name  # Extract only the 'name' field
                else:
                    data['plant_code'] = None  # or any default value
                # CounterParty
                party = counterparty_profile.objects.filter(id=data['party_name'], delete_flag=False).first()
                if party:
                    data['party_code'] = party.name  # Extract only the 'name' field
                else:
                    data['party_code'] = None  # or any default value
                if len(data['actuals']) > 0:
                    failed_actuals = 0
                    total_actuals = len(data['actuals'])
                    for detail in data['actuals']:
                        compliance_data = compliance_details.objects.filter(
                            id=detail['compliance_id'], delete_flag=False
                        ).values(
                            'compliance_group_name',
                            'compliance_name',
                            'compliance_value',
                            'compliance_criteria',
                            'effective_from',
                            'option_type',
                            'value_type'
                        ).first()
                        
                        if compliance_data:
                            if(compliance_data['value_type']=='Options'):
                                compliance_code = compliance_codes.objects.filter(id=int(compliance_data['compliance_value']), delete_flag=False).first()
                                if compliance_code:
                                        compliance_data['compliance_values'] = compliance_code.compliance_value
                            else:
                                compliance_data['compliance_values'] = compliance_data['compliance_value']
                            detail.update(compliance_data)
                            
                            if(compliance_data['compliance_criteria']):
                                config_code_details = config_codes.objects.filter(config_type = 'Compliance Criteria', config_value = compliance_data['compliance_criteria'], delete_flag=False).values('config_code')[0]
                                compliance_data['criteria_name'] = config_code_details['config_code']
                            detail.update(compliance_data)
                    for compute_actual in data['actuals']:
                        if compute_actual['actuals'] != '':
                            if compute_actual['value_type'] == 'Number':
                                if not evaluate_condition(compute_actual['actuals'],  compute_actual['compliance_values'], compute_actual['compliance_criteria']):
                                    failed_actuals = failed_actuals+1
                            elif compute_actual['value_type'] == 'Options':
                                if not evaluate_string_condition(compute_actual['actuals'],compute_actual['compliance_value'],compute_actual['compliance_criteria']):
                                    failed_actuals = failed_actuals+1
                            else:
                                if not evaluate_string_condition(compute_actual['actuals'],compute_actual['compliance_value'],compute_actual['compliance_criteria']):
                                    failed_actuals = failed_actuals+1
                        else:
                            failed_actuals = failed_actuals+1
                    print(total_actuals, failed_actuals)
                    data['status'] = str(round(100 - (failed_actuals / total_actuals * 100))) + '%'     
                if len(data['actuals']) > 0:
                    for detail in data['actuals']:
                        detail.update(compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_group_name','compliance_name','compliance_value','compliance_criteria','effective_from','option_type','value_type')[0])
                
        return Response(
            {
                "data": serializer.data,
                "data_length": details_length,
                "csv_data": serializer_csv_export.data,
            },status=status.HTTP_200_OK
        )
    except ValueError as e:
        print("e1",e)
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        # Catch other general exceptions
        print("e2",e)
        return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Insert CounterParty Details and Compliance Actuals
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_counterparty_compliance_actuals(request):
    counterparty_data = {
        "region_id": request.data.get("region_id") if request.data.get("region_id") else 'Null',
        "level_id": request.data.get("level_id"),
        "party_name": request.data.get("party_name"),
        "start_date": request.data.get("start_date"),
        "plant": request.data.get("plant"),
        "subject": request.data.get("subject"),
        "expiry_date": request.data.get("expiry_date"),
        "year": request.data.get("year"),
        "reference": request.data.get("reference"),
        "term": request.data.get("term"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }
    
    counterparty_serializer = counterparty_details_serializer(data=counterparty_data)
    
    if counterparty_serializer.is_valid():
        counterparty = counterparty_serializer.save()
        counterparty_id = counterparty.id
    
        compliance_actuals_data = request.data.get('compliance_actuals')
        
        response_data = []
        for item in compliance_actuals_data:
            item_data = {
                "compliance_id": item.get("id"),
                "counterparty_id": counterparty_id,
                "actuals": item.get("actuals"),
                "attachment": item.get("attachment"),
                "path": item.get("path"),
                "file_name": item.get("file_name"),
                "created_by": item.get("created_by"),
                "last_updated_by": item.get("last_updated_by"),
            }

            actual_serializer = compliance_actuals_serializer(data=item_data)

            if actual_serializer.is_valid():
                actual_serializer.save()
                response_data.append(actual_serializer.data)  # Collect successful inserts
            else:
                return Response(actual_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"counterparty": counterparty_serializer.data, "compliance_actuals": response_data}, status=status.HTTP_200_OK)
    else:
        return Response(counterparty_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Update CounterParty details and Compliance actuals
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_counterparty_compliance_actuals(request, id):
    # Update Counterparty details
    try:
        counterparty = counterparty_details.objects.get(id=id)
    except counterparty_details.DoesNotExist:
        return Response({"error": "Counterparty not found"}, status=status.HTTP_404_NOT_FOUND)
    
    counterparty_serializer = counterparty_details_serializer(instance=counterparty, data=request.data)
    
    if counterparty_serializer.is_valid():
        counterparty_serializer.save()
        counterparty_id = counterparty.id  # Get the counterparty ID after updating

        # Update Compliance Actuals
        compliance_actuals_data = request.data.get('compliance_actuals')
        response_data = []
        
        for item in compliance_actuals_data:
            item_id = item.get("id")
            compliance_id = item.get("compliance_id")

            if compliance_id:
                try:
                    # Update existing compliance actuals
                    compliance_item = compliance_actuals.objects.get(id=item_id, counterparty_id=counterparty_id)
                    compliance_serializer = compliance_actuals_serializer(instance=compliance_item, data=item)
                except compliance_actuals.DoesNotExist:
                    # If the compliance actual does not exist, create a new one
                    item['compliance_id'] = item_id  # Use the id as compliance_id
                    item['counterparty_id'] = counterparty_id  # Set the counterparty_id
                    compliance_serializer = compliance_actuals_serializer(data=item)

                if compliance_serializer.is_valid():
                    compliance_serializer.save()
                    response_data.append(compliance_serializer.data)
                else:
                    return Response(compliance_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                # If no compliance_id exists, use the id as compliance_id for new records
                item['compliance_id'] = item_id  # Use the id as compliance_id
                item['counterparty_id'] = counterparty_id  # Set the counterparty_id
                compliance_serializer = compliance_actuals_serializer(data=item)

                if compliance_serializer.is_valid():
                    compliance_serializer.save()
                    response_data.append(compliance_serializer.data)
                else:
                    return Response(compliance_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"counterparty": counterparty_serializer.data, "compliance_actuals": response_data}, status=status.HTTP_200_OK)
    
    return Response(counterparty_serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(["PUT"])
# @permission_classes([IsAuthenticated])
@transaction.atomic
def upd_compliance_actuals(request):
    actualsData = request.data

    for item in actualsData:
        compliance_actuals_id = item.get("id")
        if not compliance_actuals_id:
            return Response({"error": "Missing ID in one of the items"}, status=status.HTTP_400_BAD_REQUEST)

        compliance_actuals_obj = compliance_actuals.objects.filter(id=compliance_actuals_id).first()
        if not compliance_actuals_obj:
            return Response({"error": f"Compliance Actual with id {compliance_actuals_id} not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = compliance_actuals_serializer(instance=compliance_actuals_obj, data=item)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()

    return Response({"message": "All compliance actuals updated successfully"}, status=status.HTTP_200_OK)


# Delete CounterParty details
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_counterparty_details(request, id):
    item = counterparty_details.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = counterparty_details_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

# Compliance Actuals

# Get Range Compliance Actuals
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_compliance_actuals(request, start, end, search=False):
    try:
        if not search:
            details_length = compliance_actuals.objects.filter(delete_flag=False).count()
            details = compliance_actuals.objects.filter(delete_flag=False)[start:end]
        else:
            details_length = compliance_actuals.objects.filter(delete_flag=False).count()
            details = compliance_actuals.objects.filter(Q(actuals__icontains = search) | Q(attachment__icontains = search) | Q(path__icontains = search)  | Q(file_name__icontains = search), delete_flag=False)[start:end]
        details_csv_export = compliance_actuals.objects.filter(Q(actuals__icontains = search) | Q(attachment__icontains = search) | Q(path__icontains = search)  | Q(file_name__icontains = search), delete_flag=False)
        serializer = compliance_actuals_serializer(details, many=True)
        serializer_csv_export = compliance_actuals_serializer(details_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": details_length,
                "csv_data": serializer_csv_export.data,
            },status=status.HTTP_200_OK
        )
    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)

# Delete Compliance Actuals
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_compliance_actuals(request, id):
    item = compliance_actuals.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = compliance_actuals_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

# View all Compliance Details
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_details(request, id=0):
    if id == 0:
        org = compliance_details.objects.filter(delete_flag=False)
    else:
        org = compliance_details.objects.filter(id=id)
    serializer = compliance_details_serializer(org, many='N')
    if len(serializer.data) > 0:
        for data in serializer.data:
            if(data['value_type']=='Options'):
                # Compliance Code to Value
                compliance_code = compliance_codes.objects.filter(id=int(data['compliance_value']), delete_flag=False).first()
                if compliance_code:
                    data['compliance_values'] = compliance_code.compliance_value
            else:
                data['compliance_values'] = data['compliance_value']
    return Response(serializer.data)
    
# View all CounterParty Details

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_counterparty_details(request, id=0):
    if id == 0:
        org = counterparty_details.objects.filter(delete_flag=False)
        details_length = compliance_actuals.objects.filter(delete_flag=False).count()
    else:
        org = counterparty_details.objects.filter(id=id)
        details_length = compliance_actuals.objects.filter(delete_flag=False).count()
    serializer = counterparty_details_serializer(org, many=True)
    if len(serializer.data) > 0:
        for data in serializer.data:
            actuals = compliance_actuals.objects.filter(counterparty_id=data['id'], delete_flag=False)
            actuals_serializer = compliance_actuals_serializer(actuals, many=True)
            data['actuals'] = actuals_serializer.data
            if len(data['actuals']) > 0:
                for detail in data['actuals']:
                    # Plant
                    plant = plant_details.objects.filter(id=data['plant'], delete_flag=False).first()
                    if plant:
                        data['plant_code'] = plant.name  # Extract only the 'name' field
                    else:
                        data['plant_code'] = None  # or any default value
                    # CounterParty
                    party = counterparty_profile.objects.filter(id=data['party_name'], delete_flag=False).first()
                    if party:
                        data['party_code'] = party.name  # Extract only the 'name' field
                    else:
                        data['party_code'] = None  # or any default value
                    compli_details = compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_group_name','compliance_name','compliance_value','compliance_criteria','effective_from','option_type','value_type')[0]
                    
                    if(compli_details['compliance_criteria']):
                        config_code_details = config_codes.objects.filter(config_type = 'Compliance Criteria', config_value = compli_details['compliance_criteria'], delete_flag=False).values('config_code')[0] 
                        compli_details['criteria_name'] = config_code_details['config_code']
                                    
                    if(compli_details['value_type']=='Options'):
                        compliance_code = compliance_codes.objects.filter(id=int(compli_details['compliance_value']), delete_flag=False).first()
                        if compliance_code:
                            compli_details['compliance_values'] = compliance_code.compliance_value
                    else:
                        compli_details['compliance_values'] = compli_details['compliance_value']
                    detail.update(compli_details)
                    # detail.update(compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_group_name','compliance_name','compliance_value','compliance_criteria','effective_from','option_type','value_type')[0])
    
    return Response({
        "data": serializer.data,
        "data_length": details_length
        }, status=status.HTTP_200_OK)

# View all Compliance Actuals

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_actuals(request, id=0):
    try:
        if id == 0:
            org = compliance_actuals.objects.filter(delete_flag=False)
        else:
            org = compliance_actuals.objects.filter(counterparty_id=id)
        serializer = compliance_actuals_serializer(org, many=True)
        data= serializer.data
        return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)
        


# compliance Codes

# GET Range
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_range_compliance_codes(request, start, end, search=False):
    try:
        if not search:
            compliance_len = compliance_codes.objects.filter(delete_flag=False).count()
            compliance = compliance_codes.objects.filter( delete_flag=False)[start:end]
        else:
            compliance_len = compliance_codes.objects.filter(Q(compliance_type__icontains = search) | Q(compliance_code__icontains = search) | Q(compliance_value__icontains = search), delete_flag=False).count()
            compliance = compliance_codes.objects.filter(Q(compliance_type__icontains = search) | Q(compliance_code__icontains = search) | Q(compliance_value__icontains = search), delete_flag=False)[start:end]
        serializer = compliance_codes_serializer(compliance, many=True)
        compliance_data = serializer.data
        
        # Serializer for CSV data (all records)
        compliance_csv_export = compliance_codes.objects.filter(delete_flag=False)
        serializer_csv_export = compliance_codes_serializer(compliance_csv_export, many=True)
        csv_data = serializer_csv_export.data

        # Mapping to keep track of compliance_code "0" values for header lookup
        compliance_code_map = {item["compliance_code"]: item["compliance_value"] for item in csv_data}
        print("compliance_code_map :",compliance_code_map)

        # Add compliance_header to each item in compliance_data
        for item in compliance_data:
            compliance_code = item.get("compliance_code")
            
            if compliance_code == "0":
                item["compliance_header"] = "--Header--"
            else:
                # Retrieve the compliance value using the compliance_code
                head_value = compliance_codes.objects.filter(id=compliance_code, delete_flag=False).first()
                if head_value:
                    item["compliance_header"] = head_value.compliance_value
                    
        for item in csv_data:
            compliance_code = item.get("compliance_code")
            
            if compliance_code == "0":
                item["compliance_header"] = "--Header--"
            else:
                # Retrieve the compliance value using the compliance_code
                head_value = compliance_codes.objects.filter(id=compliance_code, delete_flag=False).first()
                if head_value:
                    item["compliance_header"] = head_value.compliance_value

        return Response(
            {
                "data": compliance_data,
                "data_length": compliance_len,
                "csv_data": csv_data,
            },
            status=status.HTTP_200_OK
        )

    except Exception as e:
        print("ERROR :",e)
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
    #     serializer_csv_export = compliance_codes_serializer(compliance_csv_export, many=True)
    #     return Response(
    #         {
    #             "data": serializer.data,
    #             "data_length": compliance_len,
    #             "csv_data": serializer_csv_export.data,
    #         }
    #     )
    # except Exception as e:
    #     return Response(e,status=status.HTTP_400_BAD_REQUEST)

# Get By ID
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_codes(request, id=0):
    if id == 0:
        compliance = compliance_codes.objects.filter(delete_flag=False)
    else:
        compliance = compliance_codes.objects.filter(id=id)
    serializer = compliance_codes_serializer(compliance, many=True)
    return Response(serializer.data)

# ADD
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@transaction.atomic
def ins_compliance_codes(request):
    # Check if request.data is a dictionary
    if isinstance(request.data, dict):
        # Convert to a list with a single dictionary element
        insertData = [request.data]
    else:
        # If it's already a list, keep it as is
        insertData = request.data
    # insertData = request.data
    print("Reuest Data :",insertData,"Type :",type(insertData))
    all_errors = []
    successful_inserts = []
    
    try:
        for record in insertData:
            data = {
                "compliance_type": record.get("compliance_type"),
                "compliance_code": record.get("compliance_code"),
                "compliance_value": record.get("compliance_value"),
                "created_by": record.get("created_by"),
                "last_updated_by": record.get("last_updated_by"),
                "is_active": False if record.get("is_active") is None else record.get("is_active"),
                "is_header": False if record.get("is_header") is None else record.get("is_header"),
            }

            serializer = compliance_codes_serializer(data=data)

            all_serializer_fields = list(serializer.fields.keys())
            fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']
            required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

            if serializer.is_valid():
                serializer.save()
                successful_inserts.append(serializer.data)
            else:
                error_data = serializer.errors
                e_code, e_msg, e_field = [], [], []
                
                for field, error_list in error_data.items():
                    for error_item in error_list:
                        error_code = error_item.code
                        e_code.append(error_code)
                        e_msg.append(error_item)
                        e_field.append(field)

                non_e_field = [field for field in required_serializer_fields if field not in e_field]
                data_warning = warnings.objects.filter(error_code__in=e_code, error_from="Server")
                serializer_warning = warnings_serializer(data_warning, many=True)

                field_arr = []
                for idx, code in enumerate(e_code):
                    for warning in serializer_warning.data:
                        if code == warning["error_code"]:
                            field_arr.append(warning["error_msg"].replace("%1", e_field[idx].replace("_", " ")))

                data = [{e_field[i]: [field_arr[i]]} for i in range(len(e_code))]
                data += [{field: ''} for field in non_e_field]

                def order_data(data):
                    field_order = {
                        # 'compliance_type': 0,
                        'compliance_code': 0,
                        'compliance_value': 1,
                    }
                    return sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

                ordered_data = order_data(data)
                all_errors.append({"record": record, "errors": ordered_data})

        if all_errors:
            return Response(ordered_data, status=status.HTTP_400_BAD_REQUEST)
        return Response(successful_inserts, status=status.HTTP_200_OK)

    except Exception as e:
        transaction.set_rollback(True)
        print("ERROR :", e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_compliance_codes(request, id):
    # data_dict = request.data[0]
    print("request data :",request.data)
    item = compliance_codes.objects.get(id=id)

    serializer = compliance_codes_serializer(instance=item, data=request.data)
    
    all_serializer_fields = list(serializer.fields.keys())
    
    print("serializer fields",all_serializer_fields)

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    print("required_serializer_fields",required_serializer_fields)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        print("error_data", error_data)
        e_code = []
        e_msg = []
        e_field = []
        # Iterate over each field's errors
        for field, error_list in error_data.items():
            for error_data in error_list:
                # Access the error code
                error_code = error_data.code
                e_code.append(error_code)
                e_msg.append(error_data)
                e_field.append(field)

        # print("e_code", e_code, "length", len(e_code))
        # print("e_msg", e_msg, "length", len(e_msg))
        # print("e_field", e_field, "length", len(e_field))

        # Remove the excluded fields from the list of field names
        non_e_field = [for_field for for_field in required_serializer_fields if for_field not in e_field]

        # print("non_e_field",non_e_field)

        data_warning = warnings.objects.filter(
            error_code__in=e_code, error_from="Server"
        )
        serializer_warning = warnings_serializer(data_warning, many=True)
        # print("serializer_warning length", serializer_warning.data)

        # ! test validation on Backend level

        field_arr = []
        for iter in range(len(e_code)):
            for j in serializer_warning.data:
                # print("out : ", e_code[iter], j["error_code"])
                if e_code[iter] == j["error_code"]:
                    field_arr.append(
                        (j["error_msg"]).replace("%1", e_field[iter].replace("_", " "))
                    )
                    # print("true")
                    # print("j:", j["error_msg"])
                else:
                    print("false")
                    print("i:", e_code[iter])

        # print("field_arr", field_arr)

        data = []
        for i in range(len(e_code)):
            # print(f"Error code for field '{field}': {error_code}")
            data.append({e_field[i]: [field_arr[i]]})
        # print("data", data)

        for i in range(len(non_e_field)):
            data.append({non_e_field[i]: ''})
        # print("data", data)

        def order_data(data):
            # Define the desired field order
            field_order = {
                # 'compliance_type': 0,
                'compliance_code': 0,
                'compliance_value': 1,
            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data
        print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)



# DELETE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_compliance_codes(request, id):
    item = compliance_codes.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = compliance_codes_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)
    

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_dashboard(request, region):
    try:
        compliance = compliance_details.objects.filter(delete_flag=False)
        compliance_ser_data = compliance_details_serializer(compliance, many=True)
        if len(compliance_ser_data.data) > 0:
            for data in compliance_ser_data.data:
                if(data['value_type']=='Options'):
                    # Compliance Code to Value
                    compliance_code = compliance_codes.objects.filter(id=int(data['compliance_value']), delete_flag=False).first()
                    if compliance_code:
                        data['compliance_values'] = compliance_code.compliance_value
                else:
                    data['compliance_values'] = data['compliance_value']
        if region == 'all':
            details_length = counterparty_details.objects.filter(delete_flag=False).count()
            details = counterparty_details.objects.filter(delete_flag=False)
            details_csv_export = counterparty_details.objects.filter(delete_flag=False)
        else:
            details_length = counterparty_details.objects.filter(delete_flag=False, plant__region=region).count()
            details = counterparty_details.objects.filter(delete_flag=False, plant__region=region)
            details_csv_export = counterparty_details.objects.filter(delete_flag=False, plant__region=region)
        
        serializer = counterparty_details_serializer(details, many=True)
        serializer_csv_export = counterparty_details_serializer(details_csv_export, many=True)
        if len(serializer.data) > 0:
            for data in serializer.data:
                actuals = compliance_actuals.objects.filter(counterparty_id=data['id'], delete_flag=False)
                actuals_serializer = compliance_actuals_serializer(actuals, many=True)
                data['actuals'] = actuals_serializer.data
                if len(data['actuals']) > 0:
                    for detail in data['actuals']:
                        # Plant
                        plant = plant_details.objects.filter(id=data['plant'], delete_flag=False).first()
                        if plant:
                            data['plant_code'] = plant.name  # Extract only the 'name' field
                        else:
                            data['plant_code'] = None  # or any default value
                        # CounterParty
                        party = counterparty_profile.objects.filter(id=data['party_name'], delete_flag=False).first()
                        if party:
                            data['party_code'] = party.name  # Extract only the 'name' field
                        else:
                            data['party_code'] = None  # or any default value
                        
                        compli_details = compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_name','compliance_value','compliance_criteria','value_type')[0]
                        if(compli_details['value_type']=='Options'):
                            compliance_code = compliance_codes.objects.filter(id=int(compli_details['compliance_value']), delete_flag=False).first()
                            if compliance_code:
                                compli_details['compliance_values'] = compliance_code.compliance_value
                                if detail['actuals'] != '':
                                    detail['actuals'] = compliance_codes.objects.filter(id=int(detail['actuals']), delete_flag=False).first().compliance_value
                        else:
                            compli_details['compliance_values'] = compli_details['compliance_value']
                        detail.update(compli_details)
        
        return Response(
            {
                "data": serializer.data,
                "compliance_details": compliance_ser_data.data,
                "csv_data": serializer_csv_export.data,
            },status=status.HTTP_200_OK
        )
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        # Catch other general exceptions
        return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def filter_counterparty(data, filter_column, condition):
    filtered_data = []
    for cp_data in data:
        if cp_data[filter_column] == condition:
            filtered_data.append(cp_data)
    return filtered_data
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_summary_v2(request, region='all', year = '',plant=''):
    try:
        compliance = compliance_details.objects.filter(delete_flag=False)
        compliance_ser_data = compliance_details_serializer(compliance, many=True)
        if len(compliance_ser_data.data) > 0:
            for data in compliance_ser_data.data:
                if(data['value_type']=='Options'):
                    # Compliance Code to Value
                    compliance_code = compliance_codes.objects.filter(id=int(data['compliance_value']), delete_flag=False).first()
                    if compliance_code:
                        data['compliance_values'] = compliance_code.compliance_value
                else:
                    data['compliance_values'] = data['compliance_value']
        if region == 'all':
            if plant != '':
                details = plant_details.objects.filter(id=plant,delete_flag=False)
            else:
                details = plant_details.objects.filter(delete_flag=False)
        else:
            if plant != '':
                details = plant_details.objects.filter(id=plant, delete_flag=False, region=region)
            else:
                details = plant_details.objects.filter(delete_flag=False, region=region)
            
        
        serializer = plant_details_serializer(details, many=True)
        if len(serializer.data) > 0:
            for data in serializer.data:
                if year != '' and year != 0:
                    counterparty_data = counterparty_details.objects.filter(plant=data['id'], year= year, delete_flag=False)
                else:
                    counterparty_data = counterparty_details.objects.filter(plant=data['id'], delete_flag=False)
                counterparty_data_serializer = counterparty_details_serializer(counterparty_data, many=True)
                data['counterparty_data'] = counterparty_data_serializer.data
                tmp_counterparty_data = counterparty_data_serializer.data
                grouped_counterparty = []
                if len(counterparty_data_serializer.data) > 0:
                    for cp_data in counterparty_data_serializer.data:
                        cp_data['plant_code'] = data['name']
                        party = counterparty_profile.objects.filter(id=cp_data['party_name'], delete_flag=False).first()
                        if party:
                            cp_data['party_code'] = party.name  # Extract only the 'name' field
                        else:
                            cp_data['party_code'] = None  # or any default value
                    
                        actuals = compliance_actuals.objects.filter(counterparty_id=cp_data['id'], delete_flag=False)
                        actuals_serializer = compliance_actuals_serializer(actuals, many=True)
                        cp_data['actuals'] = actuals_serializer.data
                        if len(cp_data['actuals']) > 0:
                            for detail in cp_data['actuals']:
                                detail['plant_code'] = data['name']
                                party = counterparty_profile.objects.filter(id=cp_data['party_name'], delete_flag=False).first()
                                if party:
                                    detail['party_code'] = party.name  # Extract only the 'name' field
                                else:
                                    detail['party_code'] = None  # or any default value
                                
                                compli_details = compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_name','compliance_value','compliance_criteria','value_type')[0]
                                if(compli_details['compliance_criteria']):
                                    config_code_details = config_codes.objects.filter(config_type = 'Compliance Criteria', config_value = compli_details['compliance_criteria'], delete_flag=False).values('config_code')[0] 
                                    compli_details['criteria_name'] = config_code_details['config_code']
                                
                                if(compli_details['value_type']=='Options'):
                                    compliance_code = compliance_codes.objects.filter(id=int(compli_details['compliance_value']), delete_flag=False).first()
                                    if compliance_code:
                                        compli_details['compliance_values'] = compliance_code.compliance_value
                                        compli_details['option_type'] = compliance_code.compliance_code
                                        # compli_details['option_type'] = compliance_codes.objects.filter(id=int(detail['actuals']), delete_flag=False).first().compliance_value
                                else:
                                    compli_details['compliance_values'] = compli_details['compliance_value']

                                detail.update(compli_details)
                    for cp_name in set(cp['party_code'] for cp in counterparty_data_serializer.data):
                        grouped_counterparty.append({"party_name": cp_name, "counterparty": 
                            filter_counterparty(counterparty_data_serializer.data, 'party_code', cp_name)
                        })
                    data['counterparty_data'] = grouped_counterparty
        
        return Response(
            {
                "data": serializer.data,
            },status=status.HTTP_200_OK
        )
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        # Catch other general exceptions
        return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)        

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_summary(request, region='all'):
    try:
        compliance = compliance_details.objects.filter(delete_flag=False)
        compliance_ser_data = compliance_details_serializer(compliance, many=True)
        if len(compliance_ser_data.data) > 0:
            for data in compliance_ser_data.data:
                if(data['value_type']=='Options'):
                    # Compliance Code to Value
                    compliance_code = compliance_codes.objects.filter(id=int(data['compliance_value']), delete_flag=False).first()
                    if compliance_code:
                        data['compliance_values'] = compliance_code.compliance_value
                else:
                    data['compliance_values'] = data['compliance_value']
        if region == 'all':
            details = plant_details.objects.filter(delete_flag=False)
        else:
            details = plant_details.objects.filter(delete_flag=False, region=region)
        
        serializer = plant_details_serializer(details, many=True)
        if len(serializer.data) > 0:
            for data in serializer.data:
                counterparty_data = counterparty_details.objects.filter(plant=data['id'], delete_flag=False)
                counterparty_data_serializer = counterparty_details_serializer(counterparty_data, many=True)
                data['counterparty_data'] = counterparty_data_serializer.data
                if len(counterparty_data_serializer.data) > 0:
                    for cp_data in counterparty_data_serializer.data:
                        cp_data['plant_code'] = data['name']
                        party = counterparty_profile.objects.filter(id=cp_data['party_name'], delete_flag=False).first()
                        if party:
                            cp_data['party_code'] = party.name  # Extract only the 'name' field
                        else:
                            cp_data['party_code'] = None  # or any default value
                            
                        actuals = compliance_actuals.objects.filter(counterparty_id=cp_data['id'], delete_flag=False)
                        actuals_serializer = compliance_actuals_serializer(actuals, many=True)
                        cp_data['actuals'] = actuals_serializer.data
                        if len(cp_data['actuals']) > 0:
                            for detail in cp_data['actuals']:
                                detail['plant_code'] = data['name']
                                party = counterparty_profile.objects.filter(id=cp_data['party_name'], delete_flag=False).first()
                                if party:
                                    detail['party_code'] = party.name  # Extract only the 'name' field
                                else:
                                    detail['party_code'] = None  # or any default value
                                
                                compli_details = compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_name','compliance_value','compliance_criteria','value_type')[0]
                                if(compli_details['compliance_criteria']):
                                    config_code_details = config_codes.objects.filter(config_type = 'Compliance Criteria', config_value = compli_details['compliance_criteria'], delete_flag=False).values('config_code')[0] 
                                    compli_details['criteria_name'] = config_code_details['config_code']
                                
                                # if(compli_details['value_type']=='Options'):
                                #     compliance_code = compliance_codes.objects.filter(id=int(compli_details['compliance_value']), delete_flag=False).first()
                                #     if compliance_code:
                                #         compli_details['compliance_values'] = compliance_code.compliance_value
                                #         if detail['actuals'] != '':
                                #             detail['actuals'] = compliance_codes.objects.filter(id=int(detail['actuals']), delete_flag=False).first().compliance_value
                                # else:
                                #     compli_details['compliance_values'] = compli_details['compliance_value']
                                # compli_details['compliance_values'] = compli_details['compliance_value']
                                
                                if(compli_details['value_type']=='Options'):
                                    compliance_code = compliance_codes.objects.filter(id=int(compli_details['compliance_value']), delete_flag=False).first()
                                    if compliance_code:
                                        compli_details['compliance_values'] = compliance_code.compliance_value
                                        compli_details['option_type'] = compliance_code.compliance_code
                                        # compli_details['option_type'] = compliance_codes.objects.filter(id=int(detail['actuals']), delete_flag=False).first().compliance_value
                                else:
                                    compli_details['compliance_values'] = compli_details['compliance_value']

                                detail.update(compli_details)
        
        return Response(
            {
                "data": serializer.data,
            },status=status.HTTP_200_OK
        )
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        # Catch other general exceptions
        return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    
# Get employee registration details
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def getEmpRegDetails(request):
    user = request.user
    employee = User.objects.all()
    serializer = RegisterSerializer(employee, many=True)
    return Response(serializer.data)

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def ins_upd_counterparty_profile(request):
    masterdata = request.data
    for i in range(len(masterdata)):
        if 'id' in masterdata[i]:
            data = {
                'entity_type' : masterdata[i]['entity_type'],
                'name' : masterdata[i]['name'],
                'address' : masterdata[i]['address'],
                'city_postal_code' : masterdata[i]['city_postal_code'],
                'state' : masterdata[i]['state'],
                'country' : masterdata[i]['country'],
                'created_by' : masterdata[i]['created_by'],
                'last_updated_by' : masterdata[i]['last_updated_by'],
            }
            existing_profile = counterparty_profile.objects.get(id=masterdata[i]['id'])
            serializer = counterparty_profile_serializer(instance=existing_profile, data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                print("Error", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            data = {
                'entity_type' : masterdata[i]['entity_type'],
                'name' : masterdata[i]['name'],
                'address' : masterdata[i]['address'],
                'city_postal_code' : masterdata[i]['city_postal_code'],
                'state' : masterdata[i]['state'],
                'country' : masterdata[i]['country'],
                'created_by' : masterdata[i]['created_by'],
                'last_updated_by' : masterdata[i]['last_updated_by'],
            }
            serializer = counterparty_profile_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                print("Error", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_counterparty_profile(request, id=0):
    if id == 0:
        profile = counterparty_profile.objects.filter(delete_flag=False)
    else:
        profile = counterparty_profile.objects.filter(id=id, delete_flag=False)
    serializer = counterparty_profile_serializer(profile, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_counterparty_profile(request, start, end, search=False):
    try:
        if not search:
            details_length = counterparty_profile.objects.filter(delete_flag=False).count()
            details = counterparty_profile.objects.filter(delete_flag=False)[start:end]
        else:
            details_length = counterparty_profile.objects.filter(delete_flag=False).count()
            details = counterparty_profile.objects.filter(Q(name__icontains = search) | Q(entity_type__icontains = search) | Q(address__icontains = search) | Q(country__icontains = search) | Q(state__icontains = search), delete_flag=False)[start:end]
        details_csv_export = counterparty_profile.objects.filter(delete_flag=False)
        serializer = counterparty_profile_serializer(details, many=True)
        serializer_csv_export = counterparty_profile_serializer(details_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": details_length,
                "csv_data": serializer_csv_export.data,
            }, status=status.HTTP_200_OK
        )
    except Exception as e:
        return Response(e, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_counterparty_profile(request, id):
    item = counterparty_profile.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = counterparty_profile_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

# Plant details API
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def ins_upd_plant_details(request):
    masterdata = request.data
    for i in range(len(masterdata)):
        if 'id' in masterdata[i]:
            data = {
                'name' : masterdata[i]['name'],
                'code' : masterdata[i]['code'],
                'region' : masterdata[i]['region'],
                'created_by' : masterdata[i]['created_by'],
                'last_updated_by' : masterdata[i]['last_updated_by'],
            }
            existing_profile = plant_details.objects.get(id=masterdata[i]['id'])
            serializer = plant_details_serializer(instance=existing_profile, data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                print("Error", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            data = {
                'name' : masterdata[i]['name'],
                'code' : masterdata[i]['code'],
                'region' : masterdata[i]['region'],
                'created_by' : masterdata[i]['created_by'],
                'last_updated_by' : masterdata[i]['last_updated_by'],
            }
            serializer = plant_details_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                print("Error", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_plant_details(request, id=0):
    if id == 0:
        profile = plant_details.objects.filter(delete_flag=False)
    else:
        profile = plant_details.objects.filter(id=id, delete_flag=False)
    serializer = plant_details_serializer(profile, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_plant_details(request, start, end, search=False):
    try:
        if not search:
            details_length = plant_details.objects.filter(delete_flag=False).count()
            details = plant_details.objects.filter(delete_flag=False)[start:end]
        else:
            details_length = plant_details.objects.filter(delete_flag=False).count()
            details = plant_details.objects.filter(Q(name__icontains = search) | Q(code__icontains = search) | Q(region__icontains = search), delete_flag=False)[start:end]
        details_csv_export = plant_details.objects.filter(delete_flag=False)
        serializer = plant_details_serializer(details, many=True)
        serializer_csv_export = plant_details_serializer(details_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": details_length,
                "csv_data": serializer_csv_export.data,
            }, status=status.HTTP_200_OK
        )
    except Exception as e:
        return Response(e, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_plant_details(request, id):
    item = plant_details.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = plant_details_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

@permission_classes([IsAuthenticated])
class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    # permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer


@permission_classes([IsAuthenticated])
class ChangePasswordForAdminView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ChangePasswordForAdminSerializer

    print("ChangePasswordForAdminView")
        
# @api_view(["PUT"])
# # @permission_classes([IsAuthenticated])  
# # @parser_classes([MultiPartParser, FormParser])  
# def FilePost(request):  

#     Conterparty_obj = counterparty_details.objects.get(id=request.data.get('Counterparty_id'))

#     file_data = request.FILES.get('file')  
#     file_name = request.data.get('name')
#     Counterparty_id = Conterparty_obj
#     created_by = request.data.get('created_by')
#     last_updated_by = request.data.get('last_updated_by')

#     if not file_data or not file_name:
#         fileObj = FileStore.objects.get(Counterparty_id=request.data.get('Counterparty_id'), delete_flag=False)
#         if not fileObj:
#             return Response({'error': 'File and name are required.'}, status=status.HTTP_400_BAD_REQUEST)

#         fileObj.delete_flag = True
#         fileObj.save()
#         return Response({'message': 'File Deleted successfully.'}, status=status.HTTP_201_CREATED)
        
#     content_type = file_data.content_type
#     binary_file_data = file_data.read()
#     my_file = FileStore(name=file_name, file=binary_file_data, content_type=content_type, Counterparty_id=Counterparty_id, created_by=created_by, last_updated_by=last_updated_by)

#     my_file.save()
#     return Response({'message': 'File uploaded successfully.'}, status=status.HTTP_201_CREATED)




@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def FilePost(request):
    # Start a transaction to ensure atomicity
    with transaction.atomic():

        # Track IDs of processed files
        processed_file_ids = set()

        # Retrieve counterparty details
        counterparty_id = request.data.get('Counterparty_id')
        try:
            counterparty_obj = counterparty_details.objects.get(id=counterparty_id)
        except counterparty_details.DoesNotExist:
            return Response({'error': 'Counterparty not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Initialize variables to store metadata
        created_by = request.data.get('created_by')
        last_updated_by = request.data.get('last_updated_by')

        # Retrieve all incoming files and metadata
        files = []
        for i in range(len(request.data)):
            # Extract metadata from POST data
            file_id = request.data.get(f"files[{i}][id]")
            file_name = request.data.get(f"files[{i}][name]")
            binary_file_data = request.FILES.get(f"files[{i}][file]")

            if binary_file_data is None and file_name is not None:
                processed_file_ids.add(int(file_id))

            # Check if file data is present
            if binary_file_data is None and file_name is None:
                continue
            
            files.append({
                'id': file_id,
                'name': file_name,
                'file': binary_file_data
            })

        # Fetch existing files for the counterparty that aren't flagged for deletion
        existing_files = FileStore.objects.filter(Counterparty_id=counterparty_obj, delete_flag=False)
        existing_file_map = {file.id: file for file in existing_files}

        # Process each file sent in the request
        for file_data in files:

            file_id = file_data.get('id')
            file_name = file_data.get('name')
            binary_file_data = file_data.get('file')

            if file_id and file_id in existing_file_map:

                # Update existing file
                existing_file = existing_file_map[file_id]
                if binary_file_data:
                    existing_file.file.save(binary_file_data.name, binary_file_data)  # Save the new file content
                existing_file.name = file_name  # Update the name if provided
                existing_file.last_updated_by = last_updated_by
                existing_file.save()
                processed_file_ids.add(int(file_id))

            elif binary_file_data:

                # Create a new file entry
                new_file = FileStore(
                    name=file_name,
                    file=binary_file_data.read(),  # Directly assign the file object
                    content_type=binary_file_data.content_type,
                    Counterparty_id=counterparty_obj,
                    created_by=created_by,
                    last_updated_by=last_updated_by
                )
                new_file.save()
                processed_file_ids.add(int(new_file.id))        

        # Flag any unprocessed existing files as deleted
        for existing_file in existing_files:
            if existing_file.id not in processed_file_ids:
                existing_file.delete_flag = True
                existing_file.save()

        # Retrieve all files associated with the counterparty where delete_flag is False
        currentFileData = FileStore.objects.filter(Counterparty_id=counterparty_obj, delete_flag=False)

        # Prepare the response data
        file_data_response = [
            {
                "id": file.id,
                "file_name": file.name,  # Adjust attributes based on your model
            }
            for file in currentFileData
        ]

    return Response({'message': 'Files processed successfully.', 'fileData': file_data_response}, status=status.HTTP_200_OK)



@api_view(["GET"])
# @permission_classes([IsAuthenticated]) 
def Fileget(request, id):
    try:
        file_instance = FileStore.objects.get(id=id)
        response = HttpResponse(file_instance.file, content_type=file_instance.content_type)
        response['Content-Disposition'] = f'attachment; filename="{file_instance.name}"'
        return response
    except FileStore.DoesNotExist:
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

    

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_file_names(request, id):
    try:
        file_instances = FileStore.objects.filter(Counterparty_id=id, delete_flag=False)
        if not file_instances.exists():
            return Response({"error": "Files not found"}, status=status.HTTP_404_NOT_FOUND)

        file_data = [
            {"id": file_instance.id, "file_name": file_instance.name} for file_instance in file_instances
        ]
        return Response(file_data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_compliance_summary(request, id=0):
#     try:
#         compliance = compliance_details.objects.filter(delete_flag=False)
#         compliance_ser_data = compliance_details_serializer(compliance, many=True)
#         details_length = counterparty_details.objects.filter(delete_flag=False).count()
#         details = counterparty_details.objects.filter(delete_flag=False)
#         details_csv_export = counterparty_details.objects.filter(delete_flag=False)
#         serializer = counterparty_details_serializer(details, many=True)
#         actuals_data = []
#         if len(serializer.data) > 0:
#             for data in serializer.data:
#                 actuals = compliance_actuals.objects.filter(counterparty_id=data['id'], delete_flag=False)
#                 actuals_serializer = compliance_actuals_serializer(actuals, many=True)
#                 actual = {}
#                 if len(actuals_serializer.data) > 0:
#                     for detail in actuals_serializer.data:
#                         # Plant
#                         plant = plant_details.objects.filter(id=data['plant'], delete_flag=False).first()
#                         if plant:
#                             detail['plant_code'] = plant.name  # Extract only the 'name' field
#                         else:
#                             detail['plant_code'] = None  # or any default value
#                         # CounterParty
#                         party = counterparty_profile.objects.filter(id=data['party_name'], delete_flag=False).first()
#                         if party:
#                             detail['party_code'] = party.name  # Extract only the 'name' field
#                         else:
#                             detail['party_code'] = None  # or any default value
#                         detail.update(compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_name','compliance_value','compliance_criteria')[0])
#                         actuals_data.append(detail)
#         serializer_csv_export = counterparty_details_serializer(details_csv_export, many=True)
#         return Response(
#             {
#                 "data": serializer.data,
#                 "actuals_data": actuals_data,
#             },status=status.HTTP_200_OK
#         )
#     except ValueError as e:
#         return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#     except Exception as e:
#         # Catch other general exceptions
#         return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		
		
# Compilance Intitive

# Get
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_sc_initiative(request, id, compid):
    initiate = initiative.objects.filter(counterparty_id=id, compliance_id=compid, delete_flag= False).values("id","counterparty_id","compliance_id","action_item","target_date","ownership","target_date","status","comments","created_by","last_updated_by")
    return Response(initiate)

# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_sc_initiative_details(request):
#     view = initiative.objects.all().values()
#     Counter_Data = (
#         counterparty_details.objects
#         .select_related('plant')  # Fetch related plant details
#         .values('id', 'party_name', 'subject', 'plant', plant_name=F('plant__name'))
#     )

#     Plant_Data = plant_details.objects.all().values('id', 'name')
#     Compilance_Data = compliance_details.objects.all().values('id','compliance_name')
#     for Data in view:
#         Data['target_date'] = Data['target_date'].strftime("%Y-%m-%d")
#         if Data['status'] == 'in_progress':
#             Data['status'] = 'In Progress'
#         elif Data['status'] == 'not_started':
#             Data['status'] = 'Not Started'
#         elif Data['status'] == 'complete':
#             Data['status'] = 'Completed'
#         if len(Counter_Data.filter(id=Data['counterparty_id_id'])) == 1:
#             Data['Plant_name'] = Counter_Data.get(id=Data['counterparty_id_id'])['plant_name']
#             Data['Counter_party'] = Counter_Data.get(id=Data['counterparty_id_id'])['party_name']  
#             Data['Subject'] = Counter_Data.get(id=Data['counterparty_id_id'])['subject']

#             Data['Counter_Data'] = Counter_Data
#             Data['Compilance_Data'] = Compilance_Data
#             Data['Plant_Data'] = Plant_Data
#     return Response(view)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_sc_initiative_details(request):
    # Get all initiative data
    view = initiative.objects.all().values()
    
    # Fetch related counterparty data with correct names and related fields
    counterparty_data = {
        item['id']: item
        for item in counterparty_details.objects.select_related('plant').values(
            'id', 'party_name', 'subject', 'plant', plant_name=F('plant__name')
        )
    }

    # Fetch plant and compliance details once
    plant_data = list(plant_details.objects.all().values('id', 'name').distinct())
    compliance_data = list(compliance_details.objects.all().values('id', 'compliance_name'))

    # Process each initiative entry
    for data in view:
        # Format the target date
        data['target_date'] = data['target_date'].strftime("%Y-%m-%d")
        
        # Update the status to a more readable format
        status_mapping = {
            'in_progress': 'In Progress',
            'not_started': 'Not Started',
            'complete': 'Completed'
        }
        data['status'] = status_mapping.get(data['status'], data['status'])

        # Add counterparty details if available
        counterparty = counterparty_data.get(data['counterparty_id_id'])
        if counterparty:

            # Try to retrieve the counterparty name from the counterparty_profile model
            try:
                party_name_obj = counterparty_profile.objects.get(id=counterparty['party_name'])
                data['Counter_party'] = party_name_obj.name  # Counterparty name
            except counterparty_profile.DoesNotExist:
                data['Counter_party'] = None  # Handle missing counterparty_profile

            # Try to retrieve the Compilance name from the compliance_details model
            try:
                Compliance_name_obj = compliance_details.objects.get(id=data['counterparty_id_id'])
                data['Compilance'] = Compliance_name_obj.compliance_name  # Counterparty name
            except compliance_details.DoesNotExist:
                data['Compilance'] = None  # Handle missing compliance_details
            
            data['Plant_name'] = counterparty['plant_name']
            data['Plant_id'] = counterparty['plant']
            data['Party_id'] = counterparty['party_name']
            data['Subject'] = counterparty['subject']

        # Add common data
        data['Counter_Data'] = list(counterparty_profile.objects.all().values('id', 'name').distinct())
        data['Compliance_Data'] = compliance_data
        data['Plant_Data'] = plant_data

    return Response(view)

# Add
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_sc_initiative(request):
    listData = request.data
    for i in range(len(listData)):
        if 'id' in listData[i]:
            item = initiative.objects.get(id=listData[i]['id'])
            serializer = initiative_serializer(instance=item, data=listData[i])
        else:
            data = {
                "counterparty_id": listData[i]["counterparty_id"],
                "compliance_id": listData[i]["compliance_id"],
                "action_item": listData[i]["action_item"],
                "target_date": listData[i]["target_date"],
                "ownership": listData[i]["ownership"],
                "status": listData[i]["status"],
                "comments": listData[i]["comments"] if 'comments' in listData[i] else '' ,
                "created_by": listData[i]["created_by"],
                "last_updated_by": listData[i]["last_updated_by"],
            }
            serializer = initiative_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ? SSO New User Creation API
@api_view(["POST"])
def sso_create_and_initialize_user(request):
    try:
        # Step 1: Extract data from the request
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password", "defaultpassword")
        group_id = request.data.get("group_id")
        profile_data = {
            "profile_pic": request.data.get("profile_pic"),
            "temporary_address": request.data.get("temporary_address", ""),
            "permanent_address": request.data.get("permanent_address", ""),
            "contact": request.data.get("contact", ""),
            "user_group": request.data.get("user_group"),
            "user_status": request.data.get("user_status", True),
            "created_by": request.data.get("created_by"),
            "last_updated_by": request.data.get("last_updated_by"),
        }

        # Step 2: Check if the user already exists
        if User.objects.filter(username=username).exists():
            print("User already exist")
            return Response({"message": "User already exists"}, status=status.HTTP_400_BAD_REQUEST)

        # Step 3: Create the user
        user = User.objects.create_user(username=username, email=email, password=password)

        # Step 4: Add the user to the specified group
        if group_id:
            group = Group.objects.get(id=group_id)
            user.groups.add(group)

        # Step 5: Insert user profile details
        profile_data["user_id"] = user.id
        serializer = user_profile_serializer(data=profile_data)
        if serializer.is_valid():
            serializer.save()
        else:
            print("Error :",serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "User created and initialized successfully"}, status=status.HTTP_200_OK)

    except Group.DoesNotExist:
        print("Group Does'nt exist")
        return Response({"error": "Group does not exist"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# Get active user's sessions in session table
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_user_activity(request, id=0):
    session_data = session.objects.filter().values("id","uid","logintime","lasttime","expired","status")
    set_temp = []
    for s_data in session_data:
        if len(set_temp) == 0:
            s_data['inactive_session'] = len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 0, session_data)))
            s_data['active_session'] =len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 1, session_data)))
            if(len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 1, session_data))) != 0):
                s_data['status'] = 'Active'
                s_data['lasttime'] = ''
            else:
                s_data['status'] = 'Inactive'
                s_data['lasttime'] = list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 0, session_data))[len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 0, session_data)))-1]['lasttime']
            s_data.update(User.objects.filter(id=s_data['uid'], is_active=True).values("username", "first_name", "last_name","email")[0])
            set_temp.append(s_data)
        else:
            print(list(filter(lambda x: x['uid'] != s_data['uid'], set_temp)))
            if len(list(filter(lambda x: x['uid'] != s_data['uid'], set_temp))):
                # print("-----entre-----", s_data)
                # s_data['inactive_session'] = len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 0, session_data)))
                # s_data['active_session'] =len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 1, session_data)))
                # if(len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 1, session_data))) != 0):
                #     s_data['status'] = 'Active'
                #     s_data['lasttime'] = ''
                # else:
                #     s_data['lasttime'] = str(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 0, session_data))[len(list(filter(lambda x: x['uid'] == s_data['uid'] and x['status'] == 0, session_data)))-1]['lasttime'])
                #     s_data['status'] = 'Inactive'
                # s_data.update(User.objects.filter(id=s_data['uid'], is_active=True).values("username", "first_name", "last_name","email")[0])
                set_temp.append(s_data)
    
    return Response(set_temp)

def GetIndicatorArray(id):
    indicate = org_definition_stop_light_indicators.objects.filter(delete_flag=0).values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator")
    return list(indicate)

def GetIndicator(id=0, score=0):
    color_value = 'none'
    
    indicate = org_definition_stop_light_indicators.objects.filter(delete_flag=0).values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator")
    
    for d_indicate in indicate:
        if score == 0 and (d_indicate['stop_light_indicator_from'] == 0 or d_indicate['stop_light_indicator_from'] == 1):
            color_value = d_indicate['stop_light_indicator']
        elif d_indicate['stop_light_indicator_from'] <= score and d_indicate['stop_light_indicator_to'] >= score:
            color_value = d_indicate['stop_light_indicator']
        elif score > 100:
            color_value = d_indicate['stop_light_indicator']
    return color_value

            
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_dashboard_view(request, id=0):
    org_data = []
    org_dict ={ 'score': 100,
                'indicator': GetIndicator(0, 100),
                'indicator_colors': GetIndicatorArray(0)
    }
    
    org_data.append(org_dict)
    return Response(org_data,status=status.HTTP_200_OK)

# ***Compliance Indicators***

# View all


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_compliance_indicators(request, id=0):
    if id == 0:
        comp = compliance_indicators.objects.filter(delete_flag=False)
    else:
        comp = compliance_indicators.objects.filter(id=id)

    serializer = compliance_indicators_serializer(comp, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Add


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_compliance_indicators(request):
    list_data = request.data
    
    for i in range(len(list_data)):
        data = {
            "compliance_indicator_from": list_data[i]["compliance_indicator_from"],
            "compliance_indicator_to": list_data[i]["compliance_indicator_to"],
            "compliance_indicator": list_data[i]["compliance_indicator"],
            # "def_id": list_data[i]["def_id"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        serializer = compliance_indicators_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.data, status=status.HTTP_201_CREATED)


# Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_compliance_indicators(request, id):
    list_data = request.data
    
    for i in range(len(list_data)):
        data = {
            "id": list_data[i]["id"],
            "compliance_indicator_from": list_data[i]["compliance_indicator_from"],
            "compliance_indicator_to": list_data[i]["compliance_indicator_to"],
            "compliance_indicator": list_data[i]["compliance_indicator"],
            # "def_id": list_data[i]["def_id"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        
        compliance_indictor_update = compliance_indicators.objects.filter(
            id=list_data[i]["id"]
        ).update(
            compliance_indicator_from=list_data[i]["compliance_indicator_from"],
            compliance_indicator_to=list_data[i]["compliance_indicator_to"],
            compliance_indicator=list_data[i]["compliance_indicator"],
            # def_id=list_data[i]["def_id"],
            created_by=list_data[i]["created_by"],
            last_updated_by=list_data[i]["last_updated_by"],
        )

    return Response(compliance_indictor_update, status=status.HTTP_200_OK)


# Delete


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_compliance_indicators(request, id):
    compliance_indicator_delete = compliance_indicators.objects.filter(
        delete_flag=False
    ).update(delete_flag=True)
    return Response(compliance_indicator_delete, status=status.HTTP_200_OK)
