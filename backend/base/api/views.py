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


@api_view(["GET"])
def getRoutes(request):
    routes = [
        "/api/token",
        "/api/token/refresh",
    ]

    return Response(routes)


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

    return Response(act_json)

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
    user_mail = request.data.get("email")
    group_id = request.data.get("group")

    user = User.objects.get(id=user_id)
    group = Group.objects.get(id=group_id)
    if User.objects.filter(username=user_name).exclude(id=user_id):
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    user.groups.set([group])
    user.email = user_mail
    user.username = user_name
    user.is_active = 1 if request.data.get("is_active") else 0
    user.save()

    return Response("User Updated successfully", status=status.HTTP_200_OK)


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
            subject = "This is test one"
            body = """
            <html>
            <body>
            <p>Awesome, Your SMTP credential is modified successfully.</p><br><br>\
            <i>Thanks</i>
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
                return Response(
                    "Failed to connect smtp server. Please check your details",
                    status=status.HTTP_400_BAD_REQUEST,
                )

        else:
            to = listData[i]["username"]
            subject = "This is test one"
            body = """
            <html>
            <body>
            <p>Awesome, Your SMTP credential is successfully configured.</p><br><br>\
            <i>Thanks</i>
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
        body = (
            """
            <html>
            <body>
            <div style="text-align:center;">
            <p>Hi """
            + check_email["username"].capitalize()
            + """,</p>
            <p>Congratulations. You have successfully reset your password.</p>
            <p>Please use the below password to login</p><br>
            <b style="display: inline; padding: 10px;font-size: 18px;background: cornflowerblue;">"""
            + str(randomPassword)
            + """</b><br><br>
            </div>
            <i>Thanks, <br> Cittabase</i>
            </body>
            </html>
            """
        )
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
        return Response(serializer.data, status=status.HTTP_201_CREATED)
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
        "username": request.data.get("username"),
        "profile_pic": request.data.get("profile_pic"),
        "first_name": request.data.get("first_name"),
        "last_name": request.data.get("last_name"),
        "email": request.data.get("email"),
        "temporary_address": request.data.get("temporary_address"),
        "permanent_address": request.data.get("permanent_address"),
        "contact": request.data.get("contact"),
        "user_group": request.data.get("user_group"),
        "user_status": request.data.get("user_status"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }
    if 'profile_pic' not in request.data:
        data["profile_pic"] = None
    serializer = user_profile_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Profile update

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_user_profile(request, id):
    item = user_profile.objects.get(id=id)
    data = request.data

    userStatus = 0 if data["user_status"] == 'false' else 1
    profilePic = "" if data["profile_pic"] == 'false' else data["profile_pic"]

    if item.profile_pic:
        if len(item.profile_pic) > 0 and item.profile_pic != data["profile_pic"]:
            os.remove(item.profile_pic.path)

    if item.username != data["username"]:
        item.username = data["username"]
    if item.profile_pic != profilePic:
        item.profile_pic = profilePic
    if item.first_name != data["first_name"]:
        item.first_name = data["first_name"]
    if item.last_name != data["last_name"]:
        item.last_name = data["last_name"]
    if item.email != data["email"]:
        item.email = data["email"]
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

    item.save()
    serializer = user_profile_serializer(item)
    return Response(serializer.data)
    
# Delete

@api_view(["PUT"])
# @permission_classes([IsAuthenticated])
def del_user_profile(request, id):
    Userdata = user_profile.objects.get(id=id)
    data = request.data
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
    return Response(serializer.data, status=status.HTTP_400_BAD_REQUEST)


# Update
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_functional_level(request, id):
    item = org_functional_level.objects.get(id=id)
    serializer = org_functional_level_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.data, status=status.HTTP_404_NOT_FOUND)


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
                group_serializer.save()
                for x in listData:
                    if x != '0' :
                        data = {
                            "menu_id": listData[x]["menu_id"],
                            "group_id": group_serializer.data['id'],
                            "add": listData[x]["add"] if 'add' in listData[x] else 'N',
                            "edit": listData[x]["edit"] if 'edit' in listData[x] else 'N',
                            "view": listData[x]["view"] if 'view' in listData[x] else 'N',
                            "delete": listData[x]["delete"] if 'delete' in listData[x] else 'N',
                            "created_by": listData[x]["created_by"],
                            "last_updated_by": listData[x]["last_updated_by"],
                        }
                        serializer = group_access_definition_serializer(data=data)
                        if serializer.is_valid():
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
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_navigation_menu_details(request, id=0):
    if id == 0:
        org = navigation_menu_details.objects.filter(delete_flag=False)
    else:
        org = navigation_menu_details.objects.filter(menu_id=id)

    serializer = navigation_menu_details_serializer(org, many=True)
    return Response(serializer.data)


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
            config_len = config_codes.objects.filter(delete_flag=False).count()
            config = config_codes.objects.filter(~Q(config_type = "Measure"), delete_flag=False)[start:end]
        else:
            config_len = config_codes.objects.filter(Q(config_type__icontains = search) | Q(config_code__icontains = search) | Q(config_value__icontains = search), delete_flag=False).count()
            config = config_codes.objects.filter(Q(config_type__icontains = search) | Q(config_code__icontains = search) | Q(config_value__icontains = search), delete_flag=False)[start:end]
        config_csv_export = config_codes.objects.filter(delete_flag=False)
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
def get_config_codes(request, id=0):
    if id == 0:
        config = config_codes.objects.filter(delete_flag=False)
    else:
        config = config_codes.objects.filter(id=id)
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
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_config_codes(request, id):
    item = config_codes.objects.get(id=id)

    serializer = config_codes_serializer(instance=item, data=request.data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

# DELETE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_config_codes(request, id):
    item = config_codes.objects.get(id=id)
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
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_settings(request, id):
    listData = request.data
    if not listData:
        return Response(
            {"user_id": "This field is may not be empty"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        all_item = settings.objects.all()
        for x in listData:
            if 'value' in listData[x] and listData[x]["value"] != '':
                data = {
                    "variable_name": listData[x]["variable_name"],
                    "value": listData[x]["value"],
                    "types": listData[x]["types"] if "types" in listData[x] else '',
                    "hours": int(listData[x]["hours"]) if "hours" in listData[x] else '12',
                    "seconds": int(listData[x]["seconds"]) if "seconds" in listData[x] else '00',
                    "ampm": listData[x]["ampm"] if "ampm" in listData[x] else 'am',
                    "user_id": id,
                    "created_by": listData[x]["created_by"],
                    "last_updated_by": listData[x]["last_updated_by"],
                }
                selected_item = all_item.filter(
                    variable_name=listData[x]["variable_name"], user_id=id
                ).first()
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
        updater.jobs_scheduler(id=id)
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
        return Response(
            {
                "data": serializer.data,
                "data_length": details_lengrth,
                "csv_data": serializer_csv_export.data,
            }, status=status.HTTP_200_OK
        )
    except Exception as e:
        return Response(e, status=status.HTTP_400_BAD_REQUEST)

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
    
# insert multiple compliance details
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@transaction.atomic
def ins_compliance_details_bulk(request):
    insertData = request.data
    try:
        for i in range(len(insertData)):
            data = {
                "compliance_group_name": insertData[i]["compliance_group_name"],
                "compliance_name": insertData[i]["compliance_name"],
                "compliance_criteria": insertData[i]["compliance_criteria"],
                "compliance_value": insertData[i]["compliance_value"],
                "value_type": insertData[i]["value_type"],
                "option_type": insertData[i].get('option_type') if insertData[i].get('option_type') else 'nill',
                "created_by": insertData[i]["created_by"],
                "last_updated_by": insertData[i]["last_updated_by"]
            }

            serializer = compliance_details_serializer(data=data)
            
            if serializer.is_valid():
                serializer.save()
            else:
                raise ValueError(f"Validation failed for item {i}: {serializer.errors}")

        return Response({"message": "Data inserted successfully"}, status=status.HTTP_200_OK)

    except Exception as e:
        transaction.set_rollback(True)
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    



# def ins_compliance_details_bulk(request):
#     insertData = request.data
#     for i in range(len(insertData)):
#         data = {
#             "compliance_group_name": insertData[i]["compliance_group_name"],
#             "compliance_name": insertData[i]["compliance_name"],
#             "compliance_criteria": insertData[i]["compliance_criteria"],
#             "compliance_value": insertData[i]["compliance_value"],
#             "created_by": insertData[i]["created_by"],
#             "last_updated_by": insertData[i]["last_updated_by"]
#         }
    
#         serializer = compliance_details_serializer(data=data)
    
#         if serializer.is_valid():
#             serializer.save()
#         return Response(serializer.data, status=status.HTTP_200_OK)





# update compliance details
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_compliance_details(request, id):
    item = compliance_details.objects.get(id=id)
    serializer = compliance_details_serializer(instance=item, data=request.data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

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

# Get Range CounterParty Details
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_range_counterparty_details(request, start, end, search=False):
    try:
        if not search:
            details_length = counterparty_details.objects.filter(delete_flag=False).count()
            details = counterparty_details.objects.filter(delete_flag=False)[start:end]
        else:
            details_length = counterparty_details.objects.filter(delete_flag=False).count()
            details = counterparty_details.objects.filter(Q(party_name__icontains = search) | Q(plant__icontains = search) | Q(subject__icontains = search) | Q(reference__icontains = search) | Q(term__icontains = search), delete_flag=False)[start:end]
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
                    for detail in data['actuals']:
                        # compliance_data = compliance_details.objects.filter(id=detail['compliance_id'], delete_flag=False)
                        # compliance_data_serializer = compliance_details_serializer(compliance_data, many=True)
                        # detail.update(compliance_data_serializer.data)
                        detail.update(compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_group_name','compliance_name','compliance_value','compliance_criteria','effective_from','option_type','value_type')[0])
        details_csv_export = counterparty_details.objects.filter(delete_flag=False)           
        serializer_csv_export = counterparty_details_serializer(details_csv_export, many=True)
        if len(serializer_csv_export.data) > 0:
            for data in serializer_csv_export.data:
                actuals = compliance_actuals.objects.filter(counterparty_id=data['id'], delete_flag=False)
                actuals_serializer = compliance_actuals_serializer(actuals, many=True)
                data['actuals'] = actuals_serializer.data
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
                    detail.update(compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_group_name','compliance_name','compliance_value','compliance_criteria','effective_from','option_type','value_type')[0])
    
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
@permission_classes([IsAuthenticated])
def get_range_compliance_codes(request, start, end, search=False):
    try:
        if not search:
            compliance_len = compliance_codes.objects.filter(delete_flag=False).count()
            compliance = compliance_codes.objects.filter( delete_flag=False)[start:end]
        else:
            compliance_len = compliance_codes.objects.filter(Q(compliance_type__icontains = search) | Q(compliance_code__icontains = search) | Q(compliance_value__icontains = search), delete_flag=False).count()
            compliance = compliance_codes.objects.filter(Q(compliance_type__icontains = search) | Q(compliance_code__icontains = search) | Q(compliance_value__icontains = search), delete_flag=False)[start:end]
        compliance_csv_export = compliance_codes.objects.filter(delete_flag=False)
        serializer = compliance_codes_serializer(compliance, many=True)
        serializer_csv_export = compliance_codes_serializer(compliance_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": compliance_len,
                "csv_data": serializer_csv_export.data,
            }
        )
    except Exception as e:
        return Response(e,status=status.HTTP_400_BAD_REQUEST)

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
def ins_compliance_codes(request):
    data = {
        "compliance_type": request.data.get("compliance_type"),
        "compliance_code": request.data.get("compliance_code"),
        "compliance_value": request.data.get("compliance_value"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
        "is_active": False
        if request.data.get("is_active") == None
        else request.data.get("is_active"),
    }
    serializer = compliance_codes_serializer(data=data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_compliance_codes(request, id):
    item = compliance_codes.objects.get(id=id)

    serializer = compliance_codes_serializer(instance=item, data=request.data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

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
def get_compliance_dashboard(request, id=0):
    try:
        compliance = compliance_details.objects.filter(delete_flag=False)
        compliance_ser_data = compliance_details_serializer(compliance, many=True)
        details_length = counterparty_details.objects.filter(delete_flag=False).count()
        details = counterparty_details.objects.filter(delete_flag=False)
        details_csv_export = counterparty_details.objects.filter(delete_flag=False)
        serializer = counterparty_details_serializer(details, many=True)
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
                        detail.update(compliance_details.objects.filter(id = detail['compliance_id'], delete_flag=False).values('compliance_name','compliance_value','compliance_criteria')[0])
        serializer_csv_export = counterparty_details_serializer(details_csv_export, many=True)
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
            print("------=====", masterdata[i])
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
                'location' : masterdata[i]['location'],
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
                'location' : masterdata[i]['location'],
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
            details = plant_details.objects.filter(Q(name__icontains = search) | Q(code__icontains = search) | Q(location__icontains = search), delete_flag=False)[start:end]
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