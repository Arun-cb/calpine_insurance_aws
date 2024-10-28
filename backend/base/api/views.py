from ast import Delete
from calendar import c
from distutils.command.config import config
from distutils.log import error
import json
from django.http import JsonResponse, HttpResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status, filters
from django.contrib.auth.models import User
from django.db import IntegrityError
from .serializers import *
from itertools import chain
from django.apps import apps
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from dateutil.relativedelta import relativedelta
from datetime import timedelta
from datetime import date
import calendar
from django.contrib.auth.models import User, Group
from django.db.models import Q, Max
import pandas as pd
from sqlalchemy import create_engine
import datetime
from django.conf import settings as def_set
from sqlalchemy import text
from base.api import smtp_mail
import string
import random
from django.shortcuts import get_object_or_404
import os
from django.db import connection
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from django.http import HttpRequest
from rest_framework.pagination import PageNumberPagination
import time
import numpy as np

import mysql.connector as sqlConnect
import cx_Oracle
from . import updater
from itertools import zip_longest
from office365.sharepoint.client_context import ClientContext
from urllib.parse import urlparse

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

    # def get_serializer_class(self):

    #     username = self.kwargs['username']
        # print("usenam",username,type(username))
    #     if(username!="null"):
    #         json_data = ConvertQuerysetToJson(User.objects.filter(username = username))
            # print("data dict",json_data,type(json_data),json_data.get('is_staff'))
    #         staff = json_data.get('is_staff')
    #         if staff==True:
    #         # staff==True:  # Your condition here
    #             return MyTokenObtainPairSerializer
    #         else:
    #             return MyTokenObtainPairSerializer
    #             # raise PermissionDenied("User is not staff and cannot generate a token.")
    #     else:
    #         return MyTokenObtainPairSerializer

    # return Response(status=status.HTTP_400_BAD_REQUEST)
    # None

    # serializer_class = MyTokenObtainPairSerializer


# Change Password view


@api_view(["POST"])
def checking_api(request):
    data = "Hi " + request.data.get("name") + ". Welcome to Cittabase."
    return Response(data)


@api_view(["POST"])
def change_password(request):
    # print(request.data.get("npassword"))
    username = request.data.get("username")
    npassword = request.data.get("npassword")
    u = User.objects.get(username=username)
    u.set_password(npassword)
    u.save()
    return HttpResponse(status=200)


@permission_classes([IsAuthenticated])
class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    # permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer


# Get employee registration details
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def getEmpRegDetails(request):
    user = request.user
    employee = User.objects.all()
    serializer = RegisterSerializer(employee, many=True)
    return Response(serializer.data)


# Update user active


class UpdateActiveView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdateActiveSerializer


# Create super user


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_users(request):
    # print("user save data", request.data)

    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")
    # is_staff = True

    if User.objects.filter(username=username):
        # print("if", User.objects.filter(username=username))
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    users = User.objects.create_user(username, email, password, is_staff=1)
    temp = User.objects.filter(username=users)
    # print(temp)
    return Response("User Added successfully", status=status.HTTP_200_OK)


# Create super user
@api_view(["POST"])
def ms_save_users(request):
    # print("user data", request.data)

    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if User.objects.filter(username=username):
        # print("if", User.objects.filter(username=username))
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    users = User.objects.create_user(username, email, password)
    temp = User.objects.filter(username=users)
    # print(temp)
    return Response("User Added successfully", status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_registration(request):
    # print(request)
    is_staff = request.data.get("country")
    data = {
        "username": request.data.get("username"),
        "email": request.data.get("email"),
        "password": request.data.get("password"),
        "password2": request.data.get("cpassword"),
        "is_staff": request.data.get("country"),
        # 'no_of_org_funcational_levels': request.data.get('no_of_org_funcational_levels'),
        # 'created_by': request.data.get('created_by'),
        # 'last_updated_by': request.data.get('last_updated_by')
    }
    serializer = RegisterSerializer(data=data)
    if serializer.is_valid():
        # serializer.save()
        # print(data)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    # print(serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    # return Response(data)


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
                # print("i", j)

                temp_json = {
                    "user_id": j[0],
                    "user_name": j[1],
                    "user_mail": j[2],
                    "is_active": j[3],
                    "user_group_id": i,
                    "user_group_name": temp["name"],
                }
                act_json.append(temp_json)
        # print("act_json", act_json[start:end], len(act_json))

    except Exception as e:
        print("Exception", e)

    return Response({"data": act_json[start:end], "data_length": len(act_json)})


# Get USer Group details
@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def get_user_groups(request, id=0):
    # def get_range_perspectives(request, start, end):
    # pers_len = perspectives.objects.filter(delete_flag='N').count()
    # pers = perspectives.objects.filter(delete_flag='N')[start:end]
    # serializer = perspectives_serializer(pers, many=True)
    # return Response({"data": serializer.data, "data_length": pers_len})
    try:
        superadmin = request.data.get('is_superuser') 
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
            # group_user_dict = {
            #     group.id: group.user_set.values_list(
            #         "id", "username", "email", "is_active", "is_staff", flat=False
            #     ).filter(id=id)
            #     for group in Group.objects.all()
            # }
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
        print("Exception", e)

    return Response(act_json)


# Get User Group details range
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_user_groups(request, start, end):
    # def get_range_perspectives(request, start, end):
    # pers_len = perspectives.objects.filter(delete_flag='N').count()
    # pers = perspectives.objects.filter(delete_flag='N')[start:end]
    # serializer = perspectives_serializer(pers, many=True)
    # return Response({"data": serializer.data, "data_length": pers_len})
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
                # print("i", j)

                temp_json = {
                    "user_id": j[0],
                    "user_name": j[1],
                    "user_mail": j[2],
                    "is_active": j[3],
                    "user_group_id": i,
                    "user_group_name": temp["name"],
                }
                act_json.append(temp_json)
        # print("act_json", act_json[start:end], len(act_json))

    except Exception as e:
        print("Exception", e)

    return Response({"data": act_json[start:end], "data_length": len(act_json)})


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
        # print("if", User.objects.filter(username=user_name))
        return Response("User already exist", status=status.HTTP_400_BAD_REQUEST)
    user.groups.set([group])
    user.email = user_mail
    user.username = user_name
    user.is_active = 1 if request.data.get("is_active") else 0
    user.save()

    return Response("User Updated successfully", status=status.HTTP_200_OK)


# ***Organization definition***


# View all
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_definition(request, id=0):
    if id == 0:
        org = org_definition.objects.filter(delete_flag="N")
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
    # print(data)
    serializer = org_definition_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # print(serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_definition(request, id):
    item = org_definition.objects.get(id=id)
    # print(request.data)
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
        org = org_definition_stop_light_indicators.objects.filter(delete_flag="N")
    else:
        org = org_definition_stop_light_indicators.objects.filter(id=id)

    serializer = org_definition_stop_light_indicators_serializer(org, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Add


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_definition_stop_light_indicators(request):
    list_data = request.data
    # print(list_data, "length", len(list_data))

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
    # print("list update", list_data, "length", len(list_data), "id", id)

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
        # print("data", data)

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
    ).update(delete_flag="Y")
    return Response(org_definition_delete, status=status.HTTP_200_OK)


# ***Stop light Indicators Scorecard KPIS***

# View all


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_stop_light_indicators(request, id=0):
    if id == 0:
        org = kpi_stop_light_indicators.objects.filter(delete_flag="N")
    else:
        org = kpi_stop_light_indicators.objects.filter(id=id)

    serializer = kpi_stop_light_indicators_serializer(org, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# View by id


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_stop_light_indicators_id(request, kpi_id, id=0):
    if id == 0:
        org = kpi_stop_light_indicators.objects.filter(delete_flag="N", kpi_id=kpi_id)
    else:
        org = kpi_stop_light_indicators.objects.filter(id=id)

    serializer = kpi_stop_light_indicators_serializer(org, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Stop KPI Limit


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_stop_light_indicators_limit(request, start):
    cur_len = kpi_stop_light_indicators.objects.filter(delete_flag="N").count()
    cur = kpi_stop_light_indicators.objects.filter(delete_flag="N", kpi_id=start)
    serializer = kpi_stop_light_indicators_serializer(cur, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Add
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_kpi_stop_light_indicators(request):
    list_data = request.data

    for i in range(len(list_data)):
        data = {
            "stop_light_indicator_from": list_data[i]["stop_light_indicator_from"],
            "stop_light_indicator_to": list_data[i]["stop_light_indicator_to"],
            "stop_light_indicator": list_data[i]["stop_light_indicator"],
            "kpi_id": list_data[i]["kpi_id"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        serializer = kpi_stop_light_indicators_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # print(serializer.errors)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_kpi_stop_light_indicators(request, id):
    list_data = request.data
    # print("list update", list_data, "length", len(list_data))

    for i in range(len(list_data)):
        data = {
            "id": list_data[i]["id"],
            "stop_light_indicator_from": list_data[i]["stop_light_indicator_from"],
            "stop_light_indicator_to": list_data[i]["stop_light_indicator_to"],
            "stop_light_indicator": list_data[i]["stop_light_indicator"],
            "kpi_id": list_data[i]["kpi_id"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        # print("data", data)

        alreadyhavedata = kpi_stop_light_indicators.objects.filter(
            id=list_data[i]["id"]
        ).update(
            stop_light_indicator_from=list_data[i]["stop_light_indicator_from"],
            stop_light_indicator_to=list_data[i]["stop_light_indicator_to"],
            stop_light_indicator=list_data[i]["stop_light_indicator"],
            kpi_id=list_data[i]["kpi_id"],
            created_by=list_data[i]["created_by"],
            last_updated_by=list_data[i]["last_updated_by"],
        )
        # print("set", alreadyhavedata)

    return Response("sc_serializer.data, status=status.HTTP_201_CREATED")


# Delete


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_kpi_stop_light_indicators(request, id):
    deldefiitionstoplightindicators = kpi_stop_light_indicators.objects.filter(
        kpi_id=id
    ).update(delete_flag="Y")
    return Response(deldefiitionstoplightindicators, status=status.HTTP_200_OK)


# Organization Functional Level

# GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_org_functional_level(request, start, end, search=False):
    try:
        if not search:
            org_len = org_functional_level.objects.filter(delete_flag="N").count()
            org_lvl = org_functional_level.objects.filter(delete_flag="N")[start:end]
        else:
            org_len = org_functional_level.objects.filter(Q(hierarchy_level__icontains = search) | Q(hierarchy_name__icontains = search), delete_flag="N").count()
            org_lvl = org_functional_level.objects.filter(Q(hierarchy_level__icontains = search) | Q(hierarchy_name__icontains = search), delete_flag="N")[start:end]
        org_len_withoutfilter = org_functional_level.objects.filter(delete_flag="N").count()
        org_lvl_csv_export = org_functional_level.objects.filter(delete_flag="N")
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
        print(f"exception:{e}")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_functional_level(request, id=0):
    if id == 0:
        org = org_functional_level.objects.filter(delete_flag="N")
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

    # Print(data)

    serializer = org_functional_level_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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

        print("e_code", e_code, "length", len(e_code))
        print("e_msg", e_msg, "length", len(e_msg))
        print("e_field", e_field, "length", len(e_field))

        data_warning = warnings.objects.filter(
            error_code__in=e_code, error_from="Server"
        )
        serializer_warning = warnings_serializer(data_warning, many=True)
        # print("serializer_warning length", serializer_warning.data)

        # ! test validation on Backend level

        field_arr = []
        for iter in range(len(e_code)):
            for j in serializer_warning.data:
                if e_code[iter] == j["error_code"]:
                    field_arr.append(
                        (j["error_msg"]).replace("%1", e_field[iter].replace("_", " "))
                    )

        data = []
        for i in range(len(e_code)):
            print(f"Error code for field '{field}': {error_code}")
            data.append({e_field[i]: [field_arr[i]]})

        return Response(data, status=status.HTTP_400_BAD_REQUEST)


# Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_functional_level(request, id):
    item = org_functional_level.objects.get(id=id)
    # print(request.data)
    serializer = org_functional_level_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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
                    print("true")
                    print("j:", j["error_msg"])
                else:
                    print("false")
                    print("i:", e_code[iter])

        # print("field_arr", field_arr)

        data = []
        for i in range(len(e_code)):
            print(f"Error code for field '{field}': {error_code}")
            data.append({e_field[i]: [field_arr[i]]})
        # print("data", data)

        return Response(data, status=status.HTTP_404_NOT_FOUND)


# Delete


@api_view(["PUT"])
def del_org_functional_level(request, id):
    get_heirarchy_level = org_functional_level.objects.filter(id=id, delete_flag='N').values('hierarchy_level')
    if(len(get_heirarchy_level) == 1):
        hierarchy_level = get_heirarchy_level[0]['hierarchy_level']
        check_hierarchy = org_functional_hierarchy.objects.filter(hierarchy_level = get_heirarchy_level[0]['hierarchy_level'], delete_flag='N')
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


# Currencies Insert


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_currencies(request):
    exist = currencies.objects.filter(currency_code=request.data.get("currency_code"), currency_name=request.data.get("currency_name"), delete_flag='N')
    if len(exist) == 0:
        data = {
            "currency_code": request.data.get("currency_code"),
            "currency_name": request.data.get("currency_name"),
            "sign": request.data.get("sign"),
            "created_by": request.data.get("created_by"),
            "last_updated_by": request.data.get("last_updated_by"),
        }

        serializer = currencies_serializer(data=data)
        all_serializer_fields = list(serializer.fields.keys())

        # Fields to exclude
        fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

        # Remove the excluded fields from the list of field names
        required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]


        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

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

            print("non_e_field",non_e_field)

            data_warning = warnings.objects.filter(
                error_code__in=e_code, error_from="Server"
            )
            serializer_warning = warnings_serializer(data_warning, many=True)
            # print("serializer_warning length", serializer_warning.data)

            # ! test validation on Backend level

            field_arr = []
            for iter in range(len(e_code)):
                for j in serializer_warning.data:
                    print("out : ", e_code[iter], j["error_code"])
                    if e_code[iter] == j["error_code"]:
                        field_arr.append(
                            (j["error_msg"]).replace("%1", e_field[iter].replace("_", " "))
                        )
                        print("true")
                        print("j:", j["error_msg"])
                    else:
                        print("false")
                        print("i:", e_code[iter])

            # print("field_arr", field_arr)

            data = []
            for i in range(len(e_code)):
                # print(f"Error code for field '{field}': {error_code}")
                # print(f"Errors '{e_field[i]}': {field_arr[i]}")
                data.append({e_field[i]: [field_arr[i]]})
            
            for i in range(len(non_e_field)):
                data.append({non_e_field[i]: ''})

            def order_data(data):
                # Define the desired field order
                field_order = {
                    'currency_code': 0,
                    'currency_name': 1,
                    'sign': 2,
                }

                # Sort the data based on the field order
                sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

                return sorted_data
        
            # Order the data
            ordered_data = order_data(data)

            # Print the ordered data
            return Response(ordered_data, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response('Already Exist', status=status.HTTP_200_OK)


# Get Currencies
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_currencies(request):
    cur = currencies.objects.filter(delete_flag="N")
    serializer = currencies_serializer(cur, many=True)
    return Response(serializer.data)


# Currencies Limit API Call


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_currencies(request, start, end, search=False):
    try:
        if not search:
            cur_len = currencies.objects.filter(delete_flag="N").count()
            cur = currencies.objects.filter(delete_flag="N")[start:end]
        else:
            cur_len = currencies.objects.filter(Q(currency_code__icontains = search) | Q(currency_name__icontains = search) | Q(sign__icontains = search), delete_flag="N").count()
            cur = currencies.objects.filter(Q(currency_code__icontains = search) | Q(currency_name__icontains = search) | Q(sign__icontains = search), delete_flag="N")[start:end]
        cur_csv_export = currencies.objects.filter(delete_flag="N")
        serializer = currencies_serializer(cur, many=True)
        serializer_csv_export = currencies_serializer(cur_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": cur_len,
                "csv_data": serializer_csv_export.data,
            }
        )
    except Exception as e:
        print(f"exception:{e}")



# Perspectives Limit API Call


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_currenciesmodal(request, start, end):
    cur = currencies.objects.filter(delete_flag="N")[start:end]

    serializer = currencies_serializer(cur, many=True)
    return Response(serializer.data)


# Currencies Update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_currencies(request, id):
    item = currencies.objects.get(id=id, delete_flag='N')
    exist = currencies.objects.filter(currency_code=request.data.get("currency_code"), currency_name=request.data.get("currency_name"), delete_flag='N').values()
    
    if len(exist) == 0:
        serializer = currencies_serializer(instance=item, data=request.data)
        all_serializer_fields = list(serializer.fields.keys())

        # Fields to exclude
        fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

        # Remove the excluded fields from the list of field names
        required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

        # print("required_serializer_fields",required_serializer_fields)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            error_data = serializer.errors
            # print("error_data", error_data, len(error_data))
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
                    'currency_code': 0,
                    'currency_name': 1,
                    'sign': 2,
                }

                # Sort the data based on the field order
                sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

                return sorted_data
        
            # Order the data
            ordered_data = order_data(data)
            return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)
    else:
        if request.data.get('id') != exist[0]['id']:
            return Response('Already Exist', status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_201_CREATED)

# Currencies Delete


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_currencies(request, id):
    CurView = currencies.objects.get(id=id)
    data = request.data

    if CurView.delete_flag != data["delete_flag"]:
        CurView.delete_flag = data["delete_flag"]

    CurView.save()

    serializer = currencies_serializer(CurView)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Partialfilter Currencies code


class search_currency_code(generics.ListAPIView):
    queryset = currencies.objects.filter(delete_flag="N")
    serializer_class = currencies_serializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["$currency_code", "$currency_name"]


# perspective testing views
# Partialfilter Perspective


class search_perspective(generics.ListAPIView):
    queryset = perspectives.objects.filter(delete_flag="N")
    serializer_class = perspectives_serializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["$perspective", "$description"]


# Perspectives Limit API Call


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_perspective(request, start, end):
    cur = perspectives.objects.filter(delete_flag="N")[start:end]

    serializer = perspectives_serializer(cur, many=True)
    return Response(serializer.data)


# Multisearch comma seperated perspective


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def multifilterccodeperspective(request, perspective):
    currencies_dual = perspectives.objects.all()
    ccode = perspective.split(",")
    currencies_dual = perspectives.objects.filter(perspective__in=ccode)
    serializer = perspectives_serializer(currencies_dual, many=True)
    return Response(serializer.data)


# FOR configs


class search_config_type(generics.ListAPIView):
    queryset = config_codes.objects.filter(delete_flag="N")
    serializer_class = config_codes_serializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["$config_type"]


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def multifilterconfigtype(request, config_type):
    currencies_dual = config_codes.objects.all()
    ccode = config_type.split(",")
    currencies_dual = config_codes.objects.filter(config_type__in=ccode)
    serializer = config_codes_serializer(currencies_dual, many=True)
    return Response(serializer.data)


# Partialfilter Currencies name


class search_currency_name(generics.ListAPIView):
    queryset = currencies.objects.all()
    serializer_class = currencies_serializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["$currency_name"]


# # Partialfilter Currencies dual
# @api_view(['GET'])
# # @permission_classes([IsAuthenticated])
# def search_currency_dual(request, currency_code, currency_name):

#     currencies_dual = currencies.objects.all()
#     currencies_dual = currencies.objects.filter(
#         currency_code__iregex=currency_code, currency_name__iregex=currency_name)
#     serializer = currencies_serializer(currencies_dual, many=True)
#     return Response(serializer.data)

# Partialfilter Currencies dual


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def search_currency_dual(request, currency_code, currency_name):
    currencies_dual = currencies.objects.all()
    ccode = currency_code.split(",")
    cname = currency_name.split(",")
    currencies_dual = currencies.objects.filter(
        currency_code__in=ccode, currency_name__in=cname
    )
    serializer = currencies_serializer(currencies_dual, many=True)
    return Response(serializer.data)


# Multisearch comma seperated currency code


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def multifilterccode(request, currency_code):
    currencies_dual = currencies.objects.all()
    ccode = currency_code.split(",")
    currencies_dual = currencies.objects.filter(currency_code__in=ccode)
    serializer = currencies_serializer(currencies_dual, many=True)
    return Response(serializer.data)


# Multisearch comma seperated currency name


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def multifiltercname(request, currency_name):
    currencies_dual = currencies.objects.all()
    cname = currency_name.split(",")
    currencies_dual = currencies.objects.filter(currency_name__in=cname)
    serializer = currencies_serializer(currencies_dual, many=True)
    return Response(serializer.data)


# Organization Settings View all


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_settings(request, id=0):
    if id == 0:
        org = org_settings.objects.filter(delete_flag="N")
    else:
        org = org_settings.objects.filter(id=id)

    serializer = org_settings_serializer(org, many=True)
    return Response(serializer.data)


# Organization Settings Data Insertion


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_settings(request):
    data = {
        "fiscal_year_start": request.data.get("fiscal_year_start"),
        "week_start": request.data.get("week_start"),
        "logo": request.data.get("logo"),
        "reporting_currency": request.data.get("reporting_currency"),
        "number_format_decimals": request.data.get("number_format_decimals"),
        "number_format_comma_seperator": request.data.get(
            "number_format_comma_seperator"
        ),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = org_settings_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    print(serializer.errors)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Organization Settings update


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_org_settings(request, id):
    org_settings_view = org_settings.objects.get(id=id)
    data = request.data

    if len(org_settings_view.logo) > 0 and org_settings_view.logo != data["logo"]:
        print("path", org_settings_view.logo.path)
        os.remove(org_settings_view.logo.path)

    flag = True
    currencies_obj = currencies.objects.get(id=data["reporting_currency"])
    if org_settings_view.fiscal_year_start != data["fiscal_year_start"]:
        org_settings_view.fiscal_year_start = data["fiscal_year_start"]
    if org_settings_view.week_start != data["week_start"]:
        org_settings_view.week_start = data["week_start"]
    if org_settings_view.logo != data["logo"]:
        org_settings_view.logo = data["logo"]
    if org_settings_view.reporting_currency != currencies_obj:
        org_settings_view.reporting_currency = currencies_obj
    if org_settings_view.number_format_decimals != data["number_format_decimals"]:
        if data["number_format_decimals"] != "":
            org_settings_view.number_format_decimals = data["number_format_decimals"]
            flag = True
        else:
            org_settings_view.number_format_decimals = None
            flag = False
    if (
        org_settings_view.number_format_comma_seperator
        != data["number_format_comma_seperator"]
    ):
        org_settings_view.number_format_comma_seperator = data[
            "number_format_comma_seperator"
        ]
    if org_settings_view.created_by != data["created_by"]:
        org_settings_view.created_by = data["created_by"]
    if org_settings_view.last_updated_by != data["last_updated_by"]:
        org_settings_view.last_updated_by = data["last_updated_by"]

    if flag == False:
        return Response(
            {"number_format_decimals": "Number Format Decimals is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        org_settings_view.save()
        serializer = org_settings_serializer(org_settings_view)
        return Response(serializer.data)
    # serializer = org_settings_serializer(org_settings_view)

    # return Response(serializer.data)
    # if serializer.is_valid():
    #     serializer.save()

    # print(serializer.errors)


# @api_view(['PUT'])
# @permission_classes([IsAuthenticated])
# def upd_org_settings(request, id):
#     item = org_settings.objects.get(id=id)
#     print(request.data)
#     serializer = org_settings_serializer(instance=item, data=request.data)

#     if serializer.is_valid():
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_200_OK)
#     else:
#         return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)

# Currencies Delete


# @api_view(['DELETE'])
# def del_org_settings(request, id):
#     event = org_settings.objects.get(id=id).delete()
#     return JsonResponse({'message': 'organization settings was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_settings(request, id):
    OrgView = org_settings.objects.get(id=id)
    data = request.data

    if OrgView.delete_flag != data["delete_flag"]:
        OrgView.delete_flag = data["delete_flag"].save()['id']

    if len(OrgView.logo) > 0:
        # print("OrgView.logo.path", OrgView.logo.path)
        os.remove(OrgView.logo.path)
        # os.remove(m_url)

    OrgView.save()

    serializer = org_settings_serializer(OrgView)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Org Functional Hierarchy


# Add Org Fun Hierarchy
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_org_functional_hierarchy(request):
    # print(request.data)
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
    else:
        # print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View all


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_org_functional_hierarchy(request, id=0):
    if id == 0:
        org = org_functional_hierarchy.objects.filter(delete_flag="N")
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
    else:
        print(data)
        return Response(data.errors, status=status.HTTP_400_BAD_REQUEST)


# Delete a Single object
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_org_functional_hierarchy(request, id):
    # print(request, id)
    # for i in range(id,4):
    #     test1 = org_functional_hierarchy.objects.get(parent_level_id=i)
    # print()
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
    # print("ID :", id)
    # for i in range(id,4):
    #     test1 = org_functional_hierarchy.objects.get(parent_level_id=i)
    print()
    OrgDelete = org_functional_hierarchy.objects.filter(
        main_parent_id=id_1, hierarchy_level__gt=id_2, parent_level_id=id_3
    ).update(delete_flag="Y")
    # org = org_functional_hierarchy.objects.get(main_parent_id=id)
    # data = request.data
    # print("Data :",data,OrgDelete,"length")
    # for i in range(0,len(OrgDelete)):
        # print("I :",OrgDelete[i].functional_level_id)
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

    print("Length :",len(fun_id_array),fun_id_array)

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

    # print("length",len(list_level),"unique :",list_level)
    # Loop End

    # Setting Delete flag to Y
    Delete_flag_trigger = org_functional_hierarchy.objects.filter(
        functional_level_id__in=list_level
    ).update(delete_flag="Y")

    # print("Triggered set :",Delete_flag_trigger)

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
    # print("listData", listData, "length", len(listData))
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
            try:
                serializer.save()
            except IntegrityError:
                print(IntegrityError)
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
        #     # print("data", data)
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
        org = navigation_menu_details.objects.filter(delete_flag="N")
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
    # print(request.data)
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
    # print(listData)
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
    print(type(listData))
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


# Get Menu


@api_view(["GET"])
def get_menu_access_view(request):
    data = user_access_definition.objects.all()
    serializer = user_access_serail(data, many=True)
    return Response(serializer.data)


# User


# View all
@api_view(["GET"])
@permission_classes([IsAuthenticated])
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
        print(reports.query)
    data = user_user_access_serializer(
        reports, many=True, context={"request": request}
    ).data
    return Response(data, status=status.HTTP_200_OK)


# Join group and group_access_definition table view
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def group_group_access(request, id=0, menu_id=0):
    if id == 0:
        org = navigation_menu_details.objects.filter(delete_flag="N")
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
        org = user_access_definition.objects.filter(delete_flag="N")
    else:
        org = user_access_definition.objects.filter(user_id=id)

    serializer = user_access_definition_serializer(org, many=True)
    return Response(serializer.data)


# get group access definition


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_group_access_definition(request, id=0):
    if id == 0:
        org = group_access_definition.objects.filter(delete_flag="N")
    else:
        org = group_access_definition.objects.filter(group_id=id)

    serializer = group_access_definition_serializer(org, many=True)
    return Response(serializer.data)


# Config Codes


# GET
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_config_codes(request, start, end, search=False):
    try:
        if not search:
            config_len = config_codes.objects.filter(delete_flag="N").count()
            config = config_codes.objects.filter(~Q(config_type = "Measure"), delete_flag="N")[start:end]
        else:
            config_len = config_codes.objects.filter(Q(config_type__icontains = search) | Q(config_code__icontains = search) | Q(config_value__icontains = search), delete_flag="N").count()
            config = config_codes.objects.filter(Q(config_type__icontains = search) | Q(config_code__icontains = search) | Q(config_value__icontains = search), delete_flag="N")[start:end]
        config_csv_export = config_codes.objects.filter(delete_flag="N")
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
        print(f"exception:{e}")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_config_codes(request, id=0):
    if id == 0:
        config = config_codes.objects.filter(delete_flag="N")
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
    # print("data", data)
    serializer = config_codes_serializer(data=data)
    
    all_serializer_fields = list(serializer.fields.keys())

    # print("all_serializer_fields",all_serializer_fields)

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    # print("required_serializer_fields",required_serializer_fields)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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

        index_to_replace = e_field.index('non_field_errors')

        # Replace 'non_field_errors' with 'config_codes'
        e_field[index_to_replace] = 'config_code'
        
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
        print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)


# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_config_codes(request, id):
    item = config_codes.objects.get(id=id)
    # print(request.data)

    serializer = config_codes_serializer(instance=item, data=request.data)
    
    all_serializer_fields = list(serializer.fields.keys())

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    # print("required_serializer_fields",required_serializer_fields)

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
    item = config_codes.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = config_codes_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# UOM Insert
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_uom(request):
    data = {
        "uom_code": request.data.get("uom_code"),
        "description": request.data.get("description"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = uom_serializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# UOM get
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_uom(request, start, end):
    uom_len = uom_masters.objects.filter(delete_flag="N").count()
    uom = uom_masters.objects.filter(delete_flag="N")[start:end]
    uom_csv_export = uom_masters.objects.filter(delete_flag="N")
    serializer = uom_serializer(uom, many=True)
    serializer_csv_export = uom_serializer(uom_csv_export, many=True)
    return Response(
        {
            "data": serializer.data,
            "data_length": uom_len,
            "csv_data": serializer_csv_export.data,
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_uom(request, to=0):
    if to == 0:
        pers = uom_masters.objects.filter(delete_flag="N")
    else:
        pers = uom_masters.objects.filter(id=id)
    serializer = uom_serializer(pers, many=True)
    return Response(serializer.data)


# UOM Update
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_uom(request, id):
    item = uom_masters.objects.get(id=id)
    # print(request.data)
    serializer = uom_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


# UOM Delete
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_uom(request, id):
    CurView = uom_masters.objects.get(id=id)
    data = request.data

    if CurView.delete_flag != data["delete_flag"]:
        CurView.delete_flag = data["delete_flag"]

    CurView.save()

    serializer = uom_serializer(CurView)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Perspectives

# GET

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_perspectives(request, start, end, search=False):
    try:
        if not search:
            pers_len = perspectives.objects.filter(delete_flag="N").count()
            pers = perspectives.objects.filter(delete_flag="N")[start:end]
        else:
            pers_len = perspectives.objects.filter(delete_flag="N").count()
            pers = perspectives.objects.filter(Q(perspective_code__icontains = search) | Q(perspective__icontains = search) | Q(description__icontains = search), delete_flag="N")[start:end]
        pers_csv_export = perspectives.objects.filter(Q(perspective_code__icontains = search) | Q(perspective__icontains = search) | Q(description__icontains = search), delete_flag="N")
        serializer = perspectives_serializer(pers, many=True)
        serializer_csv_export = perspectives_serializer(pers_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": pers_len,
                "csv_data": serializer_csv_export.data,
            }
        )
        
    except Exception as e:
        print(f"exception:{e}")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_perspectives(request, to=0):
    if to == 0:
        reports = perspectives.objects.filter(delete_flag="N")
        serializer = perspectives_serializer(reports, many=True)
        return Response(serializer.data)
    else:
        reports = scorecard_details.objects.select_related("perspective_id").filter(
            scorecard_id=to, delete_flag="N"
        )
        data = perspective_with_scorecard_serializer(
            reports, many=True, context={"request": request}
        ).data
        return Response(data, status=status.HTTP_200_OK)


# ADD
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_perspectives(request):
    data = {
        "perspective_code": request.data.get("perspective_code"),
        "perspective": request.data.get("perspective"),
        "description": request.data.get("description"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = perspectives_serializer(data=data)
    
    all_serializer_fields = list(serializer.fields.keys())

    print("all_serializer_fields",all_serializer_fields)

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    # print("required_serializer_fields",required_serializer_fields)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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
                'perspective_code': 0,
                'perspective': 1,
                'description': 2,
            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data
        # print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)
    

# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_perspectives(request, id):
    item = perspectives.objects.get(id=id)
    # print(request.data)

    serializer = perspectives_serializer(instance=item, data=request.data)
    all_serializer_fields = list(serializer.fields.keys())

    print("all_serializer_fields",all_serializer_fields)

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    # print("required_serializer_fields",required_serializer_fields)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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
                'perspective_code': 0,
                'perspective': 1,
                'description': 2,
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
def del_perspectives(request, id):
    item = perspectives.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = perspectives_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Bussiness goals/Objectives

# GET


@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_bussniess_goal_objective(request, sid=0, pid=0):
    if sid == 0 and pid == 0:
        goals = business_goals_objectives.objects.filter(delete_flag="N")
    else:
        goals = business_goals_objectives.objects.filter(
            scorecard_id=sid, scorecard_details_id=pid, delete_flag="N"
        )
        # print(goals.query)
    serializer = business_goals_objectives_serializer(goals, many=True)
    return Response(serializer.data)


# ADD

# @api_view(['POST'])
# # @permission_classes([IsAuthenticated])
# def ins_bussniess_goal_objective(request):
#     data = {
#         'perspective_code': request.data.get('perspective_code'),
#         'objective_code': request.data.get('objective_code'),
#         'objective': request.data.get('objective'),
#         'created_by': request.data.get('created_by'),
#         'last_updated_by': request.data.get('last_updated_by'),
#     }

#     serializer = business_goals_objectives_serializer(data=data)
#     if serializer.is_valid():
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_201_CREATED)

#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_bussniess_goal_objective(request):
    # print(request.data)
    listData = request.data
    # print(len(listData))

    for i in range(len(listData)):
        data = {
            "scorecard_id": listData[i]["scorecard_id"],
            "scorecard_details_id": listData[i]["scorecard_details_id"],
            "weight": listData[i]["weight"],
            "objective_code": listData[i]["objective_code"],
            "objective_description": listData[i]["objective_description"],
            "created_by": listData[i]["created_by"],
            "last_updated_by": listData[i]["last_updated_by"],
        }
        # print("data:", data)
        serializer = business_goals_objectives_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            # return Response(serializer.data,status=status.HTTP_200_OK)
        else:
            # print(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.data, status=status.HTTP_200_OK)


def del_child(id, feild, scorecard_id="null"):
    if scorecard_details.objects.filter(scorecard_id=id).exists() and feild == "Sc_det":
        base_item = scorecard_details.objects.filter(scorecard_id=id)
        for i in base_item:
            loop_item = scorecard_details.objects.get(id=i.id)
            delete_flag = "Y"
            if loop_item.delete_flag != delete_flag:
                loop_item.delete_flag = delete_flag
            loop_item.save()
            serializer = scorecard_details_serializer(loop_item)
            del_child(i.id, "objective")

    if (
        business_goals_objectives.objects.filter(scorecard_details_id=id).exists()
        and feild == "objective"
    ):
        base_item = business_goals_objectives.objects.filter(
            scorecard_details_id=id, scorecard_id=scorecard_id
        )
        for i in base_item:
            loop_item = business_goals_objectives.objects.get(id=i.id)
            delete_flag = "Y"
            if loop_item.delete_flag != delete_flag:
                loop_item.delete_flag = delete_flag
            loop_item.save()
            serializer = business_goals_objectives_serializer(loop_item)
            del_child(i.id, "kpi_det")

    if kpi_details.objects.filter(objective_id=id).exists() and feild == "kpi_det":
        base_Kpi_det_item = kpi_details.objects.filter(objective_id=id)
        for i in base_Kpi_det_item:
            loop_Kpi_det_item = kpi_details.objects.get(id=i.id)
            delete_flag = "Y"
            if loop_Kpi_det_item.delete_flag != delete_flag:
                loop_Kpi_det_item.delete_flag = delete_flag
            loop_Kpi_det_item.save
            Kpi_det_serializer = kpi_details_serializer(loop_Kpi_det_item)
            del_child(i.id, "kpi_act")

    if kpi_actuals.objects.filter(kpi_id=id).exists() and feild == "kpi_act":
        base_Kpi_act_item = kpi_actuals.objects.filter(kpi_id=id)
        for i in base_Kpi_act_item:
            loop_Kpi_act_item = kpi_actuals.objects.get(id=i.id)
            delete_flag = "Y"
            if loop_Kpi_act_item.delete_flag != delete_flag:
                loop_Kpi_act_item.delete_flag = delete_flag
            loop_Kpi_act_item.save
            Kpi_act_erializer = kpi_actuals_serializer(loop_Kpi_act_item)


# UPDATE


# temp Api for checking
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def temp_api(request, id):
    updateBuinessData = request.data

    # print(updateBuinessData)


# DELETE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_bussniess_goal_objective(request, id):
    item = business_goals_objectives.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = business_goals_objectives_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# Scorecard

# Scorecard GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_scorecard(request, start, end):
    score_len = scorecard.objects.filter(delete_flag="N").count()
    score_level = scorecard.objects.filter(delete_flag="N")[start:end]
    serializer = scorecard_serializer(score_level, many=True)
    return Response({"data": serializer.data, "data_length": score_len})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_scorecard(request, id=0):
    if id == 0:
        pers = scorecard.objects.filter(delete_flag="N")
        serializer = scorecard_serializer(pers, many=True)
        return Response(serializer.data)
    else:
        pers = scorecard.objects.filter(id=id)
        alldata = scorecard.objects.filter(delete_flag="N")
        allserializer = scorecard_serializer(alldata, many=True)
        serializer = scorecard_serializer(pers, many=True)
        return Response({"data": serializer.data, "all_data": allserializer.data})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_published_scorecard(request, id=0):
    if id == 0:
        pers = scorecard.objects.filter(delete_flag="N", publish_flag="Y")
        serializer = scorecard_serializer(pers, many=True)
        return Response(serializer.data)
    else:
        pers = scorecard.objects.filter(id=id)
        alldata = scorecard.objects.filter(delete_flag="N", publish_flag="Y")
        allserializer = scorecard_serializer(alldata, many=True)
        serializer = scorecard_serializer(pers, many=True)
        return Response({"data": serializer.data, "all_data": allserializer.data})


# Scorecard ADD


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_scorecard(request):
    errors = {}
    data = {
        "scorecard_description": request.data.get("scorecard_description"),
        "functional_hierarchy_level": request.data.get("functional_hierarchy_level"),
        "from_date": request.data.get("from_date")
        if len(request.data.get("from_date")) != 0
        else None,
        "to_date": request.data.get("to_date")
        if len(request.data.get("to_date")) != 0
        else None,
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }
    # print("data", data)
    serializer = scorecard_serializer(data=data)
    if serializer.is_valid():
        if data["from_date"] < data["to_date"]:
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            errors.update(serializer.errors)
            errors.update({"to_date": "From date is grater then To date"})
            errors.update({"from_date": "From date is grater then To date"})
            # print(errors)
            return Response(errors, status=status.HTTP_404_NOT_FOUND)
    else:
        errors.update(serializer.errors)
        # print(errors)
        return Response(errors, status=status.HTTP_404_NOT_FOUND)
    #     serializer.save()
    #     return Response(serializer.data, status=status.HTTP_201_CREATED)
    print(serializer.errors)
    # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Scorecard UPDATE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_scorecard(request, id):
    item = scorecard.objects.get(id=id)
    print(request.data)
    serializer = scorecard_serializer(instance=item, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        # print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


# Scorecard DELETE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_scorecard(request, id):
    item = scorecard.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = scorecard_serializer(item)
    del_child(item.id, "Sc_det")
    return Response(serializer.data, status=status.HTTP_200_OK)


# Scorecard Details

# Scorecard Details GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_scorecard_details(request, id=0):
    if id == 0:
        pers = scorecard_details.objects.filter(delete_flag="N")
    else:
        pers = scorecard_details.objects.filter(id=id)
    serializer = scorecard_details_serializer(pers, many=True)
    return Response(serializer.data)


# Scorecard Details ADD
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_scorecard_details(request):
    print(request.data)
    listData = request.data
    # print(listData)
    error = []
    for i in range(len(listData)):
        if "d_flag" not in listData[i]["formvalues"]:
            data = {
                "scorecard_id": listData[i]["formvalues"]["scorecard_id"],
                "weight": listData[i]["formvalues"]["weight"],
                "perspective_id": listData[i]["formvalues"]["perspective_id"],
                "created_by": listData[i]["formvalues"]["created_by"],
                "last_updated_by": listData[i]["formvalues"]["last_updated_by"],
            }
            serializer = scorecard_details_serializer(data=data)
            if serializer.is_valid():
                serializer.save()
            else:
                error.append(serializer.errors)
            formvalue_id = serializer.data["id"]
            if "goals" in listData[i]:
                for j in range(len(listData[i]["goals"])):
                    if "d_flag" not in listData[i]["goals"][j]:
                        # print("if goals")
                        goal_data = {
                            "scorecard_id": listData[i]["goals"][j]["scorecard_id"],
                            "scorecard_details_id": formvalue_id,
                            "weight": listData[i]["goals"][j]["weight"],
                            "objective_code": listData[i]["goals"][j]["objective_code"],
                            "objective_description": listData[i]["goals"][j][
                                "objective_description"
                            ],
                            "created_by": listData[i]["goals"][j]["created_by"],
                            "last_updated_by": listData[i]["goals"][j][
                                "last_updated_by"
                            ],
                        }
                        # print("if goal_data", goal_data)
                        Sc_ins_serializer = business_goals_objectives_serializer(
                            data=goal_data
                        )
                        if Sc_ins_serializer.is_valid():
                            print(
                                "if Sc_ins_serializer.is_valid()",
                                Sc_ins_serializer.is_valid(),
                            )
                            Sc_ins_serializer.save()
                        else:
                            error.append(Sc_ins_serializer.errors)
    if not error:
        return Response(status=status.HTTP_200_OK)
    else:
        # print("ins_scorecard_details error", error)
        return Response(error, status=status.HTTP_400_BAD_REQUEST)


# Scorecard Details UPDATE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_scorecard_details(request, id):
    updateData = request.data
    # key_to_lookup = 'id'
    # print("updateData", updateData)
    error = []
    for i in range(len(updateData)):
        if "d_flag" not in updateData[i]:
            data = {
                "scorecard_id": updateData[i]["scorecard_id"],
                "weight": updateData[i]["weight"],
                "perspective_id": updateData[i]["perspective_id"],
                "created_by": updateData[i]["created_by"],
                "last_updated_by": updateData[i]["last_updated_by"],
            }
            if "id" in updateData[i]:
                alreadyhavedata = scorecard_details.objects.get(id=updateData[i]["id"], delete_flag='N')
                sc_serializer = scorecard_details_serializer(
                    instance=alreadyhavedata, data=data
                )
                if sc_serializer.is_valid():
                    sc_serializer.save()
                else:
                    error.append(sc_serializer.errors)
                if len(updateData[i]["goals"]) != 0:
                    for j in range(len(updateData[i]["goals"])):
                        businessdata = {
                            "scorecard_id": updateData[i]["goals"][j]["scorecard_id"],
                            "scorecard_details_id": updateData[i]["goals"][j][
                                "scorecard_details_id"
                            ],
                            "weight": updateData[i]["goals"][j]["weight"],
                            "objective_code": updateData[i]["goals"][j][
                                "objective_code"
                            ],
                            "objective_description": updateData[i]["goals"][j][
                                "objective_description"
                            ],
                            "created_by": updateData[i]["goals"][j]["created_by"],
                            "last_updated_by": updateData[i]["goals"][j][
                                "last_updated_by"
                            ],
                        }
                        if "d_flag" not in updateData[i]["goals"][j]:
                            if "id" not in updateData[i]["goals"][j]:
                                Sc_ins_serializer = (
                                    business_goals_objectives_serializer(
                                        data=businessdata
                                    )
                                )
                                if Sc_ins_serializer.is_valid():
                                    Sc_ins_serializer.save()
                                else:
                                    error.append(Sc_ins_serializer.errors)
                            else:
                                alreadyhavedata = business_goals_objectives.objects.get(
                                    id=updateData[i]["goals"][j]["id"]
                                )
                                goal_serializer = business_goals_objectives_serializer(
                                    instance=alreadyhavedata, data=businessdata
                                )
                                if goal_serializer.is_valid():
                                    goal_serializer.save()
                                else:
                                    error.append(goal_serializer.errors)
                        else:
                            if "d_flag" in updateData[i]["goals"][j]:
                                if "id" in updateData[i]["goals"][j]:
                                    del_data = business_goals_objectives.objects.filter(
                                        id=updateData[i]["goals"][j]["id"]
                                    ).update(delete_flag="Y")
            else:
                sc_serializer = scorecard_details_serializer(data=data)
                if sc_serializer.is_valid():
                    sc_serializer.save()
                    details_id = sc_serializer.data["id"]
                    if len(updateData[i]["goals"]) != 0:
                        for j in range(len(updateData[i]["goals"])):
                            if "d_flag" not in updateData[i]["goals"][j]:
                                businessdata = {
                                    "scorecard_id": updateData[i]["goals"][j][
                                        "scorecard_id"
                                    ],
                                    "scorecard_details_id": details_id,
                                    "weight": updateData[i]["goals"][j]["weight"],
                                    "objective_code": updateData[i]["goals"][j][
                                        "objective_code"
                                    ],
                                    "objective_description": updateData[i]["goals"][j][
                                        "objective_description"
                                    ],
                                    "created_by": updateData[i]["goals"][j][
                                        "created_by"
                                    ],
                                    "last_updated_by": updateData[i]["goals"][j][
                                        "last_updated_by"
                                    ],
                                }
                                Sc_ins_serializer = (
                                    business_goals_objectives_serializer(
                                        data=businessdata
                                    )
                                )
                                if Sc_ins_serializer.is_valid():
                                    Sc_ins_serializer.save()
                                else:
                                    error.append(Sc_ins_serializer.errors)
                else:
                    error.append(sc_serializer.errors)
        else:
            del_data = scorecard_details.objects.filter(id=updateData[i]["id"]).update(
                delete_flag="Y"
            )
            get_bg_data = list(
                business_goals_objectives.objects.filter(
                    scorecard_id=updateData[i]["scorecard_id"],
                    scorecard_details_id=updateData[i]["id"],
                )
            )
            for k in get_bg_data:
                del_data = business_goals_objectives.objects.filter(id=k.id).update(
                    delete_flag="Y"
                )
    if not error:
        return Response(status=status.HTTP_200_OK)
    else:
        # print("error", error)
        return Response(error, status=status.HTTP_400_BAD_REQUEST)

    #     if key_to_lookup in updateData[i]:
    #         if 'd_flag' in updateData[i]:
    #             item = scorecard_details.objects.get(id=updateData[i]['id'])
    #             delete_flag='Y'

    #             if(item.delete_flag != delete_flag):
    #                 item.delete_flag = delete_flag

    #             item.save()
    #             serializer = scorecard_details_serializer(item)
    #             del_child(updateData[i]['perspective_id'],"objective",updateData[i]['scorecard_id'])
    #         else:
    # alreadyhavedata = scorecard_details.objects.get(id=updateData[i]['id'])
    # sc_serializer=scorecard_details_serializer(instance=alreadyhavedata, data=data)
    # if sc_serializer.is_valid():
    #     sc_serializer.save()
    #     alldata.append(sc_serializer.data)
    # # return Response(sc_serializer.data, status=status.HTTP_200_OK)
    # else:
    #     return Response(sc_serializer.errors, status=status.HTTP_404_NOT_FOUND)

    #     else:
    #         if 'd_flag' not in updateData[i]:
    #             Sc_ins_serializer = scorecard_details_serializer(data=data)
    #             if Sc_ins_serializer.is_valid():
    #                 Sc_ins_serializer.save()
    #                 alldata.append(Sc_ins_serializer.data)
    #             else:
                    # print(error,Sc_ins_serializer.errors)
    #                 return Response(Sc_ins_serializer.errors, status=status.HTTP_404_NOT_FOUND)
    #         else:
    #             item = scorecard_details.objects.get(scorecard_id=updateData[i]['scorecard_id'],perspective_id=updateData[i]['perspective_id'])
    #             delete_flag='Y'

    #             if(item.delete_flag != delete_flag):
    #                 item.delete_flag = delete_flag

    #             item.save()
    #             serializer = scorecard_details_serializer(item)
    #             del_child(updateData[i]['perspective_id'],"objective",updateData[i]['scorecard_id'])
    # print("alldata",alldata)
    # return Response(alldata, status=status.HTTP_200_OK)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_bussniess_goal_objective(request, id):
    updateBuinessData = request.data
    # print("data", updateBuinessData)
    for i in range(len(updateBuinessData)):
        businessdata = {
            "scorecard_id": updateBuinessData[i]["scorecard_id"],
            "scorecard_details_id": updateBuinessData[i]["scorecard_details_id"],
            "weight": updateBuinessData[i]["weight"],
            "objective_code": updateBuinessData[i]["objective_code"],
            "objective_description": updateBuinessData[i]["objective_description"],
            "created_by": updateBuinessData[i]["created_by"],
            "last_updated_by": updateBuinessData[i]["last_updated_by"],
        }
        if "id" in updateBuinessData[i]:
            if "d_flag" in updateBuinessData[i]:
                item = business_goals_objectives.objects.get(
                    id=updateBuinessData[i]["id"]
                )
                delete_flag = "Y"

                if item.delete_flag != delete_flag:
                    item.delete_flag = delete_flag

                item.save()
                serializer = scorecard_details_serializer(item)
                del_child(updateBuinessData[i]["id"], "kpi_det")

            else:
                alreadyhavedata = business_goals_objectives.objects.get(
                    id=updateBuinessData[i]["id"]
                )
                serializer = business_goals_objectives_serializer(
                    instance=alreadyhavedata, data=businessdata
                )
                if serializer.is_valid():
                    serializer.save()
        else:
            if "d_flag" not in updateBuinessData[i]:
                Sc_ins_serializer = business_goals_objectives_serializer(
                    data=businessdata
                )
                if Sc_ins_serializer.is_valid():
                    Sc_ins_serializer.save()
    return Response(status=status.HTTP_200_OK)


# Scorecard Details DELETE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_scorecard_details(request, id):
    item = scorecard_details.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = scorecard_details_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# KPI Details

# GET


@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_kpi_details(request, sid=0, pid=0, oid=0):
    if sid == 0 and pid == 0 and oid == 0:
        kpi = kpi_details.objects.filter(delete_flag="N")
    elif sid != 0 and pid == 0 and oid == 0:
        kpi = kpi_details.objects.filter(scorecard_id=sid, delete_flag="N")
    else:
        kpi = kpi_details.objects.filter(
            scorecard_id=sid,
            scorecard_details_id=pid,
            objective_id=oid,
            delete_flag="N",
        )
    serializer = kpi_details_serializer(kpi, many=True)
    return Response(serializer.data)


@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_kpi_details_Kid(request, kid=0):
    if kid == 0:
        kpi = kpi_details.objects.filter(delete_flag="N")
    else:
        kpi = kpi_details.objects.filter(id=kid, delete_flag="N")
    serializer = kpi_details_serializer(kpi, many=True)
    # print(f"==>> serializer: {serializer}")
    return Response(serializer.data)


# ADD
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_kpi_details(request):
    listData = request.data
    # print("listData", listData)
    error = []
    for i in range(len(listData)):
        data = {
            "perspective_id": listData[i]["perspective_id"],
            "objective_id": listData[i]["objective_id"],
            "scorecard_id": listData[i]["scorecard_id"],
            "scorecard_details_id": listData[i]["scorecard_details_id"],
            "kpi_code": listData[i]["kpi_code"],
            "kpi": listData[i]["kpi"],
            "ytd": listData[i]["ytd"],
            "frequency": listData[i]["frequency"],
            "weight": listData[i]["weight"],
            "measure": listData[i]["measure"],
            "baseline": listData[i]["baseline"],
            "target": listData[i]["target"],
            "min": listData[i]["min"],
            "max": listData[i]["max"],
            "optimization": listData[i]["optimization"],
            "chart_type": listData[i]["chart_type"],
            "period_type": listData[i]["period_type"],
            "created_by": listData[i]["created_by"],
            "last_updated_by": listData[i]["last_updated_by"],
        }
        kpi_serializer = kpi_details_serializer(data=data)
        if ("access_users" or "indicators") in listData[i]:
            if "id" in listData[i]:
                kpi_id = listData[i]["id"]
                exist_kpi = kpi_details.objects.get(id=listData[i]["id"])
                sc_serializer = kpi_details_serializer(instance=exist_kpi, data=data)
                if sc_serializer.is_valid():
                    sc_serializer.save()
                else:
                    error.append(sc_serializer.errors)
                if "indicators" in listData[i]:
                    for j in range(len(listData[i]["indicators"])):
                        data = {
                            "stop_light_indicator_from": listData[i]["indicators"][j][
                                "stop_light_indicator_from"
                            ],
                            "stop_light_indicator_to": listData[i]["indicators"][j][
                                "stop_light_indicator_to"
                            ],
                            "stop_light_indicator": listData[i]["indicators"][j][
                                "stop_light_indicator"
                            ],
                            "kpi_id": kpi_id,
                            "created_by": listData[i]["indicators"][j]["created_by"],
                            "last_updated_by": listData[i]["indicators"][j][
                                "last_updated_by"
                            ],
                        }
                        if "id" in listData[i]["indicators"][j]:
                            exist_indicators = kpi_stop_light_indicators.objects.get(
                                id=listData[i]["indicators"][j]["id"]
                            )
                            indicator_serializer = kpi_stop_light_indicators_serializer(
                                instance=exist_indicators, data=data
                            )
                        else:
                            indicator_serializer = kpi_stop_light_indicators_serializer(
                                data=data
                            )
                        if indicator_serializer.is_valid():
                            indicator_serializer.save()
                        else:
                            error.append(indicator_serializer.errors)
                Del_serializer = kpi_user_access.objects.filter(kpi_id=kpi_id)
                Del_serializer.delete()
                for user_id in listData[i]["access_users"]:
                    data = {
                        "user_id": user_id,
                        "kpi_id": kpi_id,
                        "created_by": listData[i]["created_by"],
                        "last_updated_by": listData[i]["last_updated_by"],
                    }
                    # exist_users = kpi_user_access.objects.get(kpi_id=listData[i]['id'])
                    # serializer = kpi_user_Access_serializer(instance=exist_users,data=data)
                    serializer = kpi_user_Access_serializer(data=data)
                    if serializer.is_valid():
                        serializer.save()
                    else:
                        error.append(sc_serializer.errors)
            else:
                if kpi_serializer.is_valid():
                    kpi_serializer.save()
                    kpi_id = kpi_serializer.data["id"]
                    if "indicators" in listData[i]:
                        for j in range(len(listData[i]["indicators"])):
                            data = {
                                "stop_light_indicator_from": listData[i]["indicators"][
                                    j
                                ]["stop_light_indicator_from"],
                                "stop_light_indicator_to": listData[i]["indicators"][j][
                                    "stop_light_indicator_to"
                                ],
                                "stop_light_indicator": listData[i]["indicators"][j][
                                    "stop_light_indicator"
                                ],
                                "kpi_id": kpi_id,
                                "created_by": listData[i]["indicators"][j][
                                    "created_by"
                                ],
                                "last_updated_by": listData[i]["indicators"][j][
                                    "last_updated_by"
                                ],
                            }
                            indicator_serializer = kpi_stop_light_indicators_serializer(
                                data=data
                            )
                            if indicator_serializer.is_valid():
                                indicator_serializer.save()
                            else:
                                error.append(sc_serializer.errors)
                    for user_id in listData[i]["access_users"]:
                        data = {
                            "user_id": user_id,
                            "kpi_id": kpi_id,
                            "created_by": listData[i]["created_by"],
                            "last_updated_by": listData[i]["last_updated_by"],
                        }
                        serializer = kpi_user_Access_serializer(data=data)
                        if serializer.is_valid():
                            serializer.save()
                        else:
                            error.append(sc_serializer.errors)
                else:
                    error.append(kpi_serializer.errors)
        elif "id" in listData[i]:
            exist_kpi = kpi_details.objects.get(id=listData[i]["id"])
            sc_serializer = kpi_details_serializer(instance=exist_kpi, data=data)
            if sc_serializer.is_valid():
                sc_serializer.save()
            else:
                error.append(sc_serializer.errors)
    if not error:
        return Response(status=status.HTTP_201_CREATED)
    else:
        # print("error", error)
        return Response(error, status=status.HTTP_400_BAD_REQUEST)

        print('loop data:', data)
    #     serializer = kpi_details_serializer(data=data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
        print(serializer.errors)
    # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_kpi_details(request, id):
    listData = request.data
    print("Passed Data:", listData)
    for i in range(len(listData)):
        data = {
            "perspective_id": listData[i]["perspective_id"],
            "objective_id": listData[i]["objective_id"],
            "scorecard_id": listData[i]["scorecard_id"],
            "kpi_code": listData[i]["kpi_code"],
            "kpi": listData[i]["kpi"],
            "ytd": listData[i]["ytd"],
            # 'performance': listData[i]['performance'],
            # 'score': listData[i]['score'],
            "frequency": listData[i]["frequency"],
            "weight": listData[i]["weight"],
            "measure": listData[i]["measure"],
            "baseline": listData[i]["baseline"],
            "target": listData[i]["target"],
            "min": listData[i]["min"],
            "max": listData[i]["max"],
            "optimization": listData[i]["optimization"],
            "chart_type": listData[i]["chart_type"],
            "period_type": listData[i]["period_type"],
            "created_by": listData[i]["created_by"],
            "last_updated_by": listData[i]["last_updated_by"],
        }
        item = kpi_details.objects.get(id=listData[i]["id"])
        print(request.data)
        serializer = kpi_details_serializer(instance=item, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


# DELETE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_kpi_details(request, id):
    item = kpi_details.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = kpi_details_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# ----settings---- #
# Get


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_settings(request, id=0):
    if id == 0:
        pers = settings.objects.filter(delete_flag="N")
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
                        print("001 error", serializer.errors)
                else:
                    serializer = settings_serializer(instance=selected_item, data=data)
                    if serializer.is_valid():
                        # print("002 saved", data)
                        serializer.save()
                    else:
                        print("002 error", serializer.errors)
        updater.jobs_scheduler(id=id)
        return Response("Success", status=status.HTTP_200_OK)


# validation of scorecard


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def val_scorecard(request):
    flag = False
    data = {
        "scorecard_description": request.data.get("scorecard_description"),
        # 'from_date': (request.data.get('from_date')).get('string'),
        # 'to_date': (request.data.get('to_date')).get('string'),
        "from_date": request.data.get("from_date"),
        "to_date": request.data.get("to_date"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = scorecard_serializer(data=data)
    errors = {}
    if serializer.is_valid():
        if data["from_date"] < data["to_date"]:
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            # errors.append(serializer.errors)
            errors.update(serializer.errors)
            # errors.append({'from_date':"From date is lesser then To date"})
            errors.update({"to_date": "From date is grater then To date"})
            errors.update({"from_date": "From date is grater then To date"})
            # print(errors)
            return Response(errors, status=status.HTTP_404_NOT_FOUND)
    else:
        errors.update(serializer.errors)
        # print(errors)
        return Response(errors, status=status.HTTP_404_NOT_FOUND)


# validation of business_goal_objectives


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def val_bussniess_goal_objective(request):
    listData = request.data
    errors = []
    re_data = []
    flag = False
    for i in range(len(listData)):
        data = {
            "scorecard_id": listData[i]["scorecard_id"],
            "scorecard_details_id": listData[i]["scorecard_details_id"],
            "weight": listData[i]["weight"],
            "objective_code": listData[i]["objective_code"],
            "objective_description": listData[i]["objective_description"],
            "created_by": listData[i]["created_by"],
            "last_updated_by": listData[i]["last_updated_by"],
        }
        serializer = business_goals_objectives_serializer(data=data)
        if serializer.is_valid():
            re_data.append(serializer.data)
            errors.append({})
        else:
            if (
                ("scorecard_id" in serializer.errors)
                or ("scorecard_details_id" in serializer.errors)
            ) and (
                ("Invalid pk" in serializer.errors["scorecard_id"][0])
                or ("Invalid pk" in serializer.errors["scorecard_details_id"][0])
            ):
                temp = serializer.errors
                temp.pop("scorecard_id")
                temp.pop("scorecard_details_id")
                # if temp:
                #     errors.append(temp)
                if len(temp) != 0:
                    flag = True
                    errors.append(temp)
                else:
                    errors.append(temp)
            # elif('scorecard_details_id' in serializer.errors and 'Invalid pk' in serializer.errors['scorecard_details_id'][0]):
            #     temp=serializer.errors
            #     temp.pop('scorecard_details_id')
            #     if temp:
            #         errors.append(temp)

            # Non feild errors content

            # elif('non_field_errors' in serializer.errors and 'must make a unique set' in serializer.errors['non_field_errors'][0]):
            #     temp=serializer.errors
            #     temp.pop('non_field_errors')
            #     # if temp:
            #     #     errors.append(temp)
            #     if len(temp)!=0:
            #         flag=True
            #         errors.append(temp)
            #     else:
            #         errors.append(temp)
            else:
                errors.append(serializer.errors)
    if flag:
        # print("errors", errors)
        return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(re_data, status=status.HTTP_200_OK)


# @api_view(['POST'])
# # @permission_classes([IsAuthenticated])
# def val_bussniess_goal_objective(request):
#     listData = request.data
#     errors={}
#     re_data={}

#     for i in range(len(listData)):
#         data ={
#             'scorecard_id' : listData[i]['scorecard_id'],
#             'scorecard_details_id' : listData[i]['scorecard_details_id'],
#             'weight' : listData[i]['weight'],
#             'objective_code' : listData[i]['objective_code'],
#             'objective_description' : listData[i]['objective_description'],
#             'created_by' : listData[i]['created_by'],
#             'last_updated_by' : listData[i]['last_updated_by']
#         }
        # print('data:',data)
#         serializer = business_goals_objectives_serializer(data=data)
#         if serializer.is_valid():
#             re_data.update(serializer.data)
#         else:
#             if('Invalid pk' in serializer.errors['scorecard_details_id'][0] and 'Invalid pk' in serializer.errors['scorecard_id'][0]):
#                 errors.update(serializer.errors)
#                 errors.pop('scorecard_details_id')
#                 errors.pop('scorecard_id')
                # print(errors)
#             else:
#                 errors.update(serializer.errors)
            # print(serializer.errors['scorecard_details_id'][0])
    # print(len(errors))
#     if(len(errors)):
        print("errors",errors)
#         return Response(errors,status=status.HTTP_400_BAD_REQUEST)
#     else:
        # print("data",re_data)
#         return Response(re_data,status=status.HTTP_200_OK)


# validation of scorecard details


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def val_scorecard_details(request):
    listData = request.data
    errors = []
    re_data = []
    flag = False

    for i in range(len(listData)):
        data = {
            "scorecard_id": listData[i]["scorecard_id"],
            "weight": listData[i]["weight"],
            "perspective_id": listData[i]["perspective_id"],
            "created_by": listData[i]["created_by"],
            "last_updated_by": listData[i]["last_updated_by"],
        }
        serializer = scorecard_details_serializer(data=data)
        if serializer.is_valid():
            re_data.append(serializer.data)
            errors.append({})
        else:
            if (
                "scorecard_id" in serializer.errors
                and "Invalid pk" in serializer.errors["scorecard_id"][0]
            ):
                temp = serializer.errors
                temp.pop("scorecard_id")
                # print(len(temp))
                if len(temp) != 0:
                    flag = True
                    errors.append(temp)
                else:
                    errors.append(temp)
            elif (
                "non_field_errors" in serializer.errors
                and "must make a unique set" in serializer.errors["non_field_errors"][0]
            ):
                temp = serializer.errors
                temp.pop("non_field_errors")
                if len(temp) != 0:
                    flag = True
                    errors.append(temp)
                else:
                    errors.append(temp)
            else:
                flag = True
                errors.append(serializer.errors)
    # print(flag)
    if flag:
        # print("errors", errors)
        return Response(errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        # print("data", re_data)
        return Response(re_data, status=status.HTTP_200_OK)


# --KPI Actuals---

# GET


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_actuals(request, id=0):
    if id == 0:
        kpi = kpi_actuals.objects.filter(delete_flag="N")
    else:
        kpi = kpi_actuals.objects.filter(id=id)
    serializer = kpi_actuals_serializer(kpi, many=True)
    return Response(serializer.data)


# ADD


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_kpi_actuals(request):
    kpi_actual = request.data
    for i in range(len(kpi_actual)):
        kpi_actual_data = {
            "scorecard_id": kpi_actual[i]["scorecard_id"],
            "perspective_id": kpi_actual[i]["perspective_id"],
            "objective_id": kpi_actual[i]["objective_id"],
            "kpi_id": kpi_actual[i]["kpi_id"],
            "period": kpi_actual[i]["period"],
            "actuals_date": kpi_actual[i]["actuals_date"],
            "actuals": kpi_actual[i]["actuals"],
            "summery": kpi_actual[i]["summery"],
            "actuals_boolean": kpi_actual[i]["actuals_boolean"],
            "created_by": kpi_actual[i]["created_by"],
            "last_updated_by": kpi_actual[i]["last_updated_by"],
        }
        serializer = kpi_actuals_serializer(data=kpi_actual_data)
        if serializer.is_valid():
            serializer.save()
            check_actuals()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_kpi_actuals(request, id):
    start_time = time.time()
    update_actual = request.data
    temp_data = []

    for i in range(len(update_actual)):
        update_actual[i]["period"]

    for i in range(len(update_actual)):
        kpi_actual_update = {
            "scorecard_id": update_actual[i]["scorecard_id"] if "scorecard_id" in update_actual[i] else None,
            "perspective_id": update_actual[i]["perspective_id"] if "perspective_id" in update_actual[i] else None,
            "objective_id": update_actual[i]["objective_id"] if "objective_id" in update_actual[i] else None,
            "kpi_id": update_actual[i]["kpi_id"],
            "period": update_actual[i]["period"],
            "actuals_date": update_actual[i]["actuals_date"],
            "actuals": update_actual[i]["actuals"],
            "summery": update_actual[i]["summery"],
            "actuals_boolean": update_actual[i]["actuals_boolean"],
            "created_by": update_actual[i]["created_by"],
            "last_updated_by": update_actual[i]["last_updated_by"],
        }
        
        if "id" in update_actual[i]:
            item = kpi_actuals.objects.get(id=update_actual[i]["id"])
        else:
            item = []
        if item:
            actual_serializer = kpi_actuals_serializer(
                instance=item, data=kpi_actual_update
            )
            if actual_serializer.is_valid():
                actual_serializer.save()
                # check_actuals()
                temp_data.append(actual_serializer)
            else:
                return Response(
                    actual_serializer.errors, status=status.HTTP_404_NOT_FOUND
                )
        else:
            actual_serializer = kpi_actuals_serializer(data=kpi_actual_update)
            if actual_serializer.is_valid():
                actual_serializer.save()
                temp_data.append(actual_serializer)
                # check_actuals()

            else:
                return Response(
                    actual_serializer.errors, status=status.HTTP_404_NOT_FOUND
                )
    print(time.time() - start_time) 
    # check_actuals()
        
    # print(time.time() - start_time)
    return Response(actual_serializer.data, status=status.HTTP_200_OK)


# samp


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def smp_get_kpi(request, kpi_id, sc_id, obj_id, prep_id):
    smp_obj = kpi_actuals.objects.filter(
        Q(kpi_id=kpi_id)
        & Q(scorecard_id=sc_id)
        & Q(objective_id=obj_id)
        & Q(perspective_id=prep_id)
    )
    serializer = kpi_actuals_serializer(smp_obj, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def smp_get_kpi_new(request, kpi_id):
    smp_obj = kpi_actuals.objects.filter(kpi_id=kpi_id)
    serializer = kpi_actuals_serializer(smp_obj, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# DELETE


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_kpi_actuals(request, id):
    item = kpi_actuals.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = kpi_actuals_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)


# --Views for KPI---

# GET view


# @api_view(["GET"])
# # @permission_classes([IsAuthenticated])
# def get_view(request):
#     view = kpi_view.objects.all()
#     serializer = kpi_view_serializer(view, many=True)
#     return Response(serializer.data)


# GET KPI Dashboard view


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_kpi_dashboard_view(request):
#     view = kpi_dashboard_view.objects.all()
#     serializer = kpi_dashboard_view_serializer(view, many=True)
#     return Response(serializer.data)



# GET Objective Dashboard view


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_obj_dashboard_view(request):
#     view = obj_dashboard_view.objects.all()
#     serializer = obj_dashboard_view_serializer(view, many=True)
#     return Response(serializer.data)


# GET Scorecard Details Dashboard view


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_sd_dashboard_view(request):
#     view = sd_dashboard_view.objects.all()
#     serializer = sd_dashboard_view_serializer(view, many=True)
#     return Response(serializer.data)


# GET ScoreCard Dashboard view


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_sc_dashboard_view(request):
#     view = sc_dashboard_view.objects.all()
#     serializer = sc_dashboard_view_serializer(view, many=True)
#     return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_date(request, start_date, end_date, column):
    clo = {column + "__range": [start_date, end_date]}
    # print(column)
    end = end_date + timedelta(days=1)
    if start_date <= end:
        # cur = currencies.objects.filter(column__range=[start_date, end])
        cur = currencies.objects.filter(**clo)
    serializer = currencies_serializer(cur, many=True)
    return Response(serializer.data)


# KPI User Access
# @api_view(['GET'])
# # @permission_classes([IsAuthenticated])
# def get_range_date(request, start_date, end_date, column):
#     clo={column+ '__range': [start_date,end_date]}
    # print(column)
#     end= end_date + timedelta(days=1)
#     if start_date<=end:
#         # cur = currencies.objects.filter(column__range=[start_date, end])
#         cur = currencies.objects.filter(**clo)
#     serializer = currencies_serializer(cur, many=True)
#     return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_user_access(request, id=0):
    if id == 0:
        kpi = kpi_user_access.objects.filter(delete_flag="N")
    else:
        kpi = kpi_user_access.objects.filter(id=id)
    serializer = kpi_user_Access_serializer(kpi, many=True)
    return Response(serializer.data)


# # Add kPI User Access
# @api_view(['POST'])
# # @permission_classes([IsAuthenticated])
# def ins_kpi_user_access(request):
#     listdata=request.data
#     return_data=[]
#     Del_serializer=kpi_user_access.objects.filter(kpi_id=listdata[0]['kpi_id'])
#     Del_serializer.delete()
    # print("lendata",listdata)
#     for i in range(len(listdata)):
#         data = {
#             'user_id': listdata[i]['user_id'],
#             'kpi_id': listdata[i]['kpi_id'],
#             'created_by': listdata[i]['created_by'],
#             'last_updated_by': listdata[i]['last_updated_by'],
#         }
        # print("data",data)
#         serializer = kpi_user_Access_serializer(data=data)
#         if serializer.is_valid():
#             serializer.save()
#             return_data.append(serializer.data)
#         else:
            # print(serializer.errors)
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#     return Response(return_data, status=status.HTTP_201_CREATED)


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
    # print(request.data)

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
        chart_options = chart_attributes_options.objects.filter(delete_flag="N")
    else:
        chart_options = chart_attributes_options.objects.filter(id=id)

    serializer = chart_attributes_options_serializer(chart_options, many=True)
    return Response(serializer.data)


@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def get_kpi_pending_actions(request, id=0):
    superadmin = request.data.get('is_superuser') 
    if id == 0:
        org = kpi_pending_actions.objects.filter(show_flag="Y", delete_flag="N")
    else:
        group_user_dict = {
            group.id: User.objects.filter(id=id).values_list(
                "id", "username", "email", "is_active", flat=False
            ) if superadmin else group.user_set.filter(id=id).values_list(
                "id", "username", "email", "is_active", flat=False
            )
            for group in Group.objects.all()
        }
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
                # act_json.append(temp_json)
                get_notification = notification.objects.filter(
                    permission=i, show_flag=1
                ).values()
        org = kpi_pending_actions.objects.filter(user_id=id, delete_flag="N").values()
    # serializer = kpi_pending_actions_serializer(org, many=True)
    for i in range(len(list(chain(get_notification, org)))):
        list(chain(get_notification, org))[i]["unique_id"] = i
    return Response(list(chain(get_notification, org)))


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_flag_kpi_pending_actions(request, id):
    # print("enter upd_flag_kpi_pending_actions")
    item = kpi_pending_actions.objects.filter(user_id=id)
    data = request.data
    if len(item) > 0:
        for i in item:
            if i.show_flag != data["show_flag"]:
                i.show_flag = data["show_flag"]

            i.save()

        serializer = kpi_pending_actions_serializer(i)
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        return Response(status=status.HTTP_200_OK)


# ------ Kpi Pending period calc functions starts --------#

Monthly = 10


def first_day_of_week(any_day):
    day_of_week = any_day.weekday()
    days_to_subtract = (day_of_week - 0) % 7
    first_day_of_week = any_day - timedelta(days=days_to_subtract)
    return first_day_of_week


def last_day_of_week(any_day):
    day_of_week = any_day.weekday()
    days_to_subtract = (6 - day_of_week) % 7
    last_day_of_week = any_day - timedelta(days=days_to_subtract)
    return last_day_of_week


def start_of_fortnight(any_day):
    day_of_week = any_day.weekday()
    days_to_subtract = (day_of_week - 0) % 14
    start_of_fortnight = any_day - timedelta(days=days_to_subtract)
    return start_of_fortnight


def last_of_fortnight(any_day):
    day_of_week = any_day.weekday()
    days_to_subtract = (13 - day_of_week) % 14
    last_of_fortnight = any_day - timedelta(days=days_to_subtract)
    return last_of_fortnight


def last_day_of_month(any_day):
    # The day 28 exists in every month. 4 days later, it's always next month
    next_month = any_day.replace(day=28) + datetime.timedelta(days=4)
    # subtracting the number of the current day brings us back one month
    return next_month - datetime.timedelta(days=next_month.day)


def first_day_of_month(any_day):
    current_month = any_day.replace(day=1)
    return current_month


def get_quarter(month):
    return (month - 1) / 3 + 1


def get_first_day_of_the_next_quarter(day, month, year):
    if int(get_quarter(month)) < 4:
        quarter = int(get_quarter(month))
        return datetime.datetime(year, 3 * quarter - 2, 1)
    else:
        quarter = 1
        return datetime.datetime(year + 1, 3 * quarter - 2, 1)


def get_last_day_of_the_quarter(day, month, year):
    quarter = int(get_quarter(month))
    f_month = 3 * quarter
    remaining = int(f_month / 12)
    return datetime.datetime(
        year + remaining, f_month % 12 + 1, 1
    ) + datetime.timedelta(days=-1)


def get_half_yearly(month):
    return int((month - 1) / 6 + 1)


def get_last_day_of_the_half_yearly(day, month, year):
    quarter = get_half_yearly(month)
    f_month = 6 * quarter
    remaining = int(f_month / 12)
    return datetime.datetime(
        year + remaining, f_month % 12 + 1, 1
    ) + datetime.timedelta(days=-1)


def get_first_day_of_the_next_half_yearly(day, month, year):
    if get_half_yearly(month) < 2:
        quarter = int(get_quarter(month))
        return datetime.datetime(year, 6 * quarter - 2, 1)
    else:
        quarter = 1
        return datetime.datetime(year + 1, 3 * quarter - 2, 1)


def check_actuals(id=1):
    try:
        pendings = kpi_pending_actions.objects.filter(delete_flag="N")
        kpi_pendings_serializer = temporary_kpi_pending_actions_serializer(
            pendings, many=True
        )
        for i in kpi_pendings_serializer.data:
            actuals = kpi_actuals.objects.filter(kpi_id=i["kpi_id"])
            actuals_serializer = kpi_actuals_serializer(actuals, many=True)

            for j in actuals_serializer.data:
                if (
                    datetime.datetime.strptime(j["period"], "%Y-%m-%d").date()
                    < datetime.datetime.strptime(
                        i["upcoming_date"][0:10], "%Y-%m-%d"
                    ).date()
                ):
                    
                    kpi_pending_actions.objects.filter(id=i["id"]).update(
                        delete_flag="Y"
                    )
                    check_kpi_actulas()

    except Exception as e:
        print(f"Try/Catch Error:{e}")


# ! previos code of kpi pendings
# def check_kpi_pending(id=1):
#     kpi_pending = kpi_pending_actions.objects.all()
#     kpi_user = kpi_user_access.objects.filter(delete_flag='N')
#     kpi_user_serializer = kpi_user_Access_serializer(kpi_user, many=True)
#     today = datetime.datetime.today()
#     for user in kpi_user_serializer.data:
#         userid = user.pop('user_id')
#         kpiid = user.pop('kpi_id')
#         kpi = kpi_details.objects.filter(delete_flag='N', id=kpiid)
#         serializer = kpi_details_serializer(kpi, many=True)
#         for i in serializer.data:
#             freq = kpi = c_date = cr_date = kpi_date = ''
#             for key,value in i.items():
#                 if(key == 'kpi'):
#                     kpi = value
#                 if(key == 'frequency' or key == 'created_date'):
#                     if(key == 'frequency'):
#                         freq = value
#                     else:
#                         for fmt in ( '%Y-%m-%dT%H:%M:%S','%Y-%m-%d', '%d.%m.%Y', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f'):
#                             try:
#                                 try:
#                                     # kpi_date = datetime.strptime(value, fmt)
#                                     kpi_date = datetime.datetime.strptime(value, fmt)
#                                     # print(f"==>> value: {value}")
#                                     cr_date = kpi_date.strftime("%Y-%m-%d %H:%M:%S")
#                                     break
#                                 except:
#                                     continue
#                             except ValueError:
#                                 pass
#                                 raise ValueError('no valid date format found')
#                         kpi_day = kpi_date.strftime("%Y-%m-%d")
#                         today_k = today.strftime("%Y-%m-%d")
#                         day = int(kpi_date.strftime("%d"))
#                         month = int(kpi_date.strftime("%m"))
#                         year = int(kpi_date.strftime("%Y"))
#                         kpi_year = int(kpi_date.strftime("%Y"))

#                         # Upcoming date calcuation for daily
#                         if(freq.strip() == 'Daily'):

#                             if(i['period_type'] == 'End'):
#                                 chsj = kpi_day
#                             else:
#                                 chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=1)

#                             if(str(chsj) <= today_k):
#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }
#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # Upcoming date calcuation for Weekly
#                         if(freq.strip() == 'Weekly'):
#                             if(i['period_type'] == 'End'):
#                                 chsj = kpi_day
#                             else:
#                                 chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=7)

#                             if(str(chsj) <= today_k):
#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }
#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # Upcoming date calcuation for Fortnightly
#                         if(freq.strip() == 'Fortnightly'):
#                             if(i['period_type'] == 'End'):
#                                 chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=14)
#                             else:
#                                 chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=15)
#                             if(str(chsj) <= today_k):
#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }
#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # Upcoming date calcuation for Monthly
#                         if(freq.strip() == 'Monthly'):
#                             # chsj is either begining or end of actuals period
#                             if(i['period_type'] == 'End'):
#                                 chsj = last_day_of_month(datetime.datetime(year, month, day))
#                             else:
#                                 chsj = first_day_of_month(datetime.datetime(year, month, day))+timedelta(days=1)
#                             # print(f"==>> datetime.date(year, month, day): {datetime.date(year, month, day)}")
#                             # print(f"==>> last_day_of_month(datetime.date(year, month, day))+timedelta(days=1): {last_day_of_month(datetime.date(year, month, day))+timedelta(days=1)}")
#                             # print(f"==>> chsj: {chsj}")
#                             if(str(chsj) <= today_k):
#                                 # print(f"==>> today_k: {today_k}")
#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date': kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }

#                                 # print(f"==>> data: {data}")
#                                 print(f"==>> kpi_day: {kpi_day}")


#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if (kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # Upcoming date calcuation for Quarterly
#                         if(freq.strip() == 'Quarterly'):
#                             if(i['period_type'] == 'End'):
#                                 chsj = get_last_day_of_the_quarter(day,month,year)
#                             else:
#                                 # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + relativedelta(years=1) -timedelta(days=4)
#                                 # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=12, day=31)-timedelta(days=5)
#                                 chsj = get_first_day_of_the_next_quarter(day,month,year)
#                             if(str(chsj) <= today_k):
#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }
#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # Upcoming date calcuation for Half-yearly
#                         if(freq.strip() == 'Half-yearly'):
#                             if(i['period_type'] == 'End'):
#                                 chsj = get_last_day_of_the_half_yearly(day,month,year)
#                             else:
#                                 chsj = get_first_day_of_the_next_half_yearly(day,8,year)

#                             if(str(chsj) <= today_k):
#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }
#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # Upcoming date calcuation for Annualy
#                         if(freq.strip() == 'Annualy'):
#                             kpi_day = kpi_date.strftime("%Y-%m-%d")
#                             kpi_year = int(kpi_date.strftime("%Y"))
#                             today_k = today.strftime("%Y-%m-%d")
#                             if(i['period_type'] == 'End'):
#                                 chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=12, day=31)-timedelta(days=5)
#                             else:
#                                 # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + relativedelta(years=1) -timedelta(days=4)
#                                 chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=1, day=1, year=year+1)-timedelta(days=5)
#                             if(str(chsj) <= today_k):

#                                 data = {
#                                     'user_id' : userid,
#                                     'kpi' : i['kpi_code'],
#                                     'message' : i['kpi']+' is pending',
#                                     'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
#                                     'kpi_id':i["id"],
#                                     'created_by' : userid,
#                                     'last_updated_by':userid
#                                 }
#                                 if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                                     if(kpi_serializer.is_valid()):
#                                         kpi_serializer.save()
#                                 if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                                     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
#                                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                                     serializer = kpi_pending_actions_serializer(instance=item, data=data)
#                                     if serializer.is_valid():
#                                         serializer.save()

#                         # if(freq.strip() == 'Quarterly'):
#                         #     kpi_day = kpi_date.strftime("%Y-%m-%d")
#                         #     today_k = today.strftime("%Y-%m-%d")
#                         #     if(i['period_type'] == 'End'):
#                         #         chsj = kpi_day
#                         #     else:
#                         #         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=7)
#                         #     # print(chsj)
#                         #     if(str(chsj) <= today_k):
#                         #         data = {
#                         #             'user_id' : userid,
#                         #             'kpi' : i['kpi_code'],
#                         #             'message' : i['kpi']+' is pending',
#                         #             'created_by' : userid,
#                         #             'last_updated_by':userid
#                         #         }
#                         #         # print(kpi_pending.filter(kpi=i['kpi_code']))
#                         #         kpi_serializer = kpi_pending_actions_serializer(data=data)
#                         #         if (kpi_serializer.is_valid() and not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
#                         #             print(data)
#                         #             # kpi_serializer.save()


# Checks upcoming kpi actuals and push it in pending table
def dueDate_generator(lastActPeriod, frequency, period, kpi_id):
    today = date.today()
    if frequency == "Daily":
        # _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        duePerid = lastActPeriod + timedelta(days=1)
        if duePerid <= today:
            return duePerid
        else:
            return None
    if frequency == "Weekly":
        previous_date = today - timedelta(days=3)
        _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        new_date_object = lastActPeriod + timedelta(days=days_in_month)
        if period == "Beginning":
            duePerid = first_day_of_week(new_date_object)
        else:
            duePerid = last_day_of_week(new_date_object)

        if duePerid <= today or duePerid <= previous_date:
            return duePerid
        else:
            return None
    if frequency == "Fortnightly":
        previous_date = today - timedelta(days=5)
        _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        new_date_object = lastActPeriod + timedelta(days=days_in_month)
        if period == "Beginning":
            duePerid = start_of_fortnight(new_date_object)
        else:
            duePerid = last_of_fortnight(new_date_object)

        if duePerid <= today or duePerid <= previous_date:
            return duePerid
        else:
            return None
    if frequency == "Monthly":
        previous_date = today - timedelta(days=10)
        _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        new_date_object = lastActPeriod + timedelta(days=days_in_month)
        if period == "Beginning":
            duePerid = first_day_of_month(new_date_object)
        else:
            duePerid = last_day_of_month(new_date_object)

        # print(f"==>> duePerid.month != today.month: {duePerid.month != today.month}")
        # print(f"==>> today.month: {today.month}")
        # print(f"==>> duePerid.month: {duePerid.month}")

        if (
            duePerid <= today or duePerid <= previous_date
        ) and duePerid.month != today.month:
            return duePerid
        else:
            return None
    if frequency == "Quarterly":
        # print(f"==>> period: {period}")
        previous_date = today - timedelta(days=10)
        _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        new_date_object = lastActPeriod + timedelta(days=days_in_month)
        if period == "Beginning":
            duePerid = get_first_day_of_the_next_quarter(new_date_object)
        else:
            print("------",period,new_date_object, kpi_id)
            day = int(period.strftime("%d"))
            month = int(period.strftime("%m"))
            year = int(period.strftime("%Y"))
            duePerid = get_last_day_of_the_quarter(day, month, year)
            # duePerid = get_last_day_of_the_quarter(new_date_object)

        if duePerid <= today or duePerid <= previous_date:
            return duePerid
        else:
            return None
    if frequency == "Half-yearly":
        # print(f"==>> period: {period}")
        previous_date = today - timedelta(days=20)
        _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        new_date_object = lastActPeriod + timedelta(days=days_in_month)
        if period == "Beginning":
            duePerid = get_first_day_of_the_next_half_yearly(new_date_object)
        else:
            duePerid = get_last_day_of_the_half_yearly(new_date_object)

        if duePerid <= today or duePerid <= previous_date:
            return duePerid
        else:
            return None
    # ! pendding functanality
    if frequency == "Annualy":
        _, days_in_month = calendar.monthrange(lastActPeriod.year, lastActPeriod.month)
        new_date_object = lastActPeriod + timedelta(days=days_in_month)
        if period == "Beginning":
            duePerid = first_day_of_month(new_date_object)
        else:
            duePerid = last_day_of_month(new_date_object)

        if duePerid <= today:
            return duePerid
        else:
            return None

    # print(f"==>> kpiActuals: {type(kpiActuals.period)}")
    # kpiActualsSer =kpi_actuals_serializer(kpiActuals, many=True)
    # for actualsData in kpiActualsSer.data:
    #     print(f"==>> actualsData: {actualsData}")

# ----------------START---------------------------
# def check_kpi_actulas():
#     print("callsed check_kpi_actulas")
#     kpi_pending = kpi_pending_actions.objects.all()
#     kpi_user = kpi_user_access.objects.filter(delete_flag="N")
#     kpi_user_serializer = kpi_user_Access_serializer(kpi_user, many=True)
#     today = datetime.datetime.today()
#     userid = 1

#     kpidetails = kpi_details.objects.filter(delete_flag="N")
#     kpiserializer = kpi_details_serializer(kpidetails, many=True)
#     kpi_pending_actions.objects.all().delete()
#     for kpiData in kpiserializer.data:
#         data_exists = kpi_actuals.objects.filter(
#             delete_flag="N", kpi_id=kpiData["id"]
#         ).exists()
#         if data_exists:
#             kpiActuals = kpi_actuals.objects.filter(
#                 delete_flag="N", kpi_id=kpiData["id"]
#             ).latest("period")
#             print(kpiData["period_type"])
#             dueDate = dueDate_generator(
#                 kpiActuals.period, kpiData["frequency"], kpiData["period_type"], kpiData["id"]
#             )
#             if dueDate:
#                 data = {
#                     "user_id": userid,
#                     "kpi": kpiData["kpi"],
#                     "message": kpiData["kpi"] + " is pending",
#                     "upcoming_date": dueDate.strftime("%Y-%m-%d"),
#                     "kpi_id": kpiData["id"],
#                     "action": "alert",
#                     "created_by": userid,
#                     "last_updated_by": userid,
#                 }
#                 if not kpi_pending.filter(kpi_id=kpiData["id"], user_id=userid):
#                     kpi_serializer = kpi_pending_actions_serializer(data=data)
#                     if kpi_serializer.is_valid():
#                         kpi_serializer.save()
#                     else:
#                         print(f"==>> err: {kpi_serializer.errors}")
#                 if kpi_pending.filter(kpi_id=kpiData["id"], user_id=userid):
#                     json = kpi_pending.filter(kpi_id=kpiData["id"]).values("id")
#                     item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                     serializer = kpi_pending_actions_serializer(
#                         instance=item, data=data
#                     )
#                     if serializer.is_valid():
#                         serializer.save()
#                         kpi_pending_actions.objects.filter(id=json[0]["id"]).update(
#                             delete_flag="N"
#                         )

#         else:
#             kpiActuals = None
#             scoreCard = scorecard.objects.filter(
#                 delete_flag="N", id=kpiData["scorecard_id"]
#             )
#             for data in scoreCard:
#                 # dueDate = dueDate_generator(data.from_date.date(), kpiData["frequency"], kpiData["period_type"])

#                 dueDate = data.from_date.date()
#                 if dueDate:
#                     data = {
#                         "user_id": userid,
#                         "kpi": kpiData["kpi"],
#                         "message": kpiData["kpi"] + " is pending",
#                         "upcoming_date": dueDate.strftime("%Y-%m-%d"),
#                         "action": "alert",
#                         "kpi_id": kpiData["id"],
#                         "created_by": userid,
#                         "last_updated_by": userid,
#                     }
#                     if not kpi_pending.filter(kpi_id=kpiData["id"], user_id=userid):
#                         kpi_serializer = kpi_pending_actions_serializer(data=data)
#                         if kpi_serializer.is_valid():
#                             kpi_serializer.save()
#                         else:
#                             print(f"==>> err: {kpi_serializer.errors}")

#                     if kpi_pending.filter(kpi_id=kpiData["id"], user_id=userid):
#                         json = kpi_pending.filter(kpi_id=kpiData["id"]).values("id")
#                         item = kpi_pending_actions.objects.get(id=json[0]["id"])
#                         serializer = kpi_pending_actions_serializer(
#                             instance=item, data=data
#                         )
#                         if serializer.is_valid():
#                             serializer.save()
#                             kpi_pending_actions.objects.filter(id=json[0]["id"]).update(
#                                 delete_flag="N"
#                             )

# --------------------END---------------------

def first_day_of_week(any_day):
    day_of_week = any_day.weekday()
    days_to_subtract = (day_of_week - 0) % 7
    first_day_of_week = any_day - timedelta(days=days_to_subtract)
    return first_day_of_week


def last_day_of_week(any_day):
    day_of_week = any_day.weekday()
    days_to_subtract = (6 - day_of_week) % 7
    last_day_of_week = any_day - timedelta(days=days_to_subtract)
    return last_day_of_week

def last_day_of_month(any_day):
    # The day 28 exists in every month. 4 days later, it's always next month
    next_month = any_day.replace(day=28) + datetime.timedelta(days=4)
    # subtracting the number of the current day brings us back one month
    return next_month - datetime.timedelta(days=next_month.day)


def first_day_of_month(any_day):
    current_month = any_day.replace(day=1)
    return current_month

# -------------------Start Old Fun---------------------------
from dateutil import relativedelta

# Remainder section
def check_monthly_actuals_remainder():
    kpi_pending = kpi_pending_actions.objects.all()
    kpi_user = kpi_user_access.objects.filter(delete_flag='N')
    kpi_user_serializer = kpi_user_Access_serializer(kpi_user, many=True)
    today = datetime.datetime.today()
    for user in kpi_user_serializer.data:
        userid = user.pop('user_id')
        kpiid = user.pop('kpi_id')
        kpi = kpi_details.objects.filter(delete_flag='N', id=kpiid).values()
        for i in kpi:
            sc_from_to_date = scorecard.objects.filter(delete_flag='N', id=i['scorecard_id_id']).values()
            if(len(sc_from_to_date) == 1):
                from_date = sc_from_to_date[0]['from_date']
                to_date = sc_from_to_date[0]['to_date']
                kpi_created_date = i['created_date'] if i['created_date'] != '' else ''
                freq = kpi = c_date = cr_date = kpi_date = todate_fromdate = ''
                kpi = i['kpi_code'] if i['kpi_code'] != '' else ''
                freq = i['frequency'] if i['frequency'] != '' else ''
                today_k = today.strftime("%Y-%m-%d")
                kpiActuals = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id']).values()
                if freq.strip() == 'Monthly':
                    if kpi_created_date >= from_date and kpi_created_date <= to_date:
                        last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                        if (to_date > today) == True:
                            # if(i['id'] == 5):
                            #     print("Checking------- ",today+relativedelta(months=+1))
                            check_exist_actual = ''
                            if(i['period_type'].strip() == 'End'):
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(last_day_of_month(today).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0 and (last_day_of_month(today) - today).days <= 7:
                                if (last_day_of_month(today) - today).days <= 7:
                                    data = {
                                        'user_id' : userid,
                                        'kpi' : i['kpi_code'],
                                        # 'message' : i['kpi_code']+' next due date is '+str(last_day_of_month(today).strftime("%Y-%m-%d")),
                                        'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(last_day_of_month(today).strftime("%Y-%m-%d")),
                                        'upcoming_date':str(last_day_of_month(today).strftime("%Y-%m-%d")),
                                        'kpi_id':i["id"],
                                        'action': "alert",
                                        'created_by' : userid,
                                        'last_updated_by':userid
                                    }
                                    if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0):
                                        kpi_serializer = kpi_pending_actions_serializer(data=data)
                                        if(kpi_serializer.is_valid()):
                                            kpi_serializer.save()
                                    else:
                                        json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                        item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                        serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                        if serializer.is_valid():
                                            serializer.save()
                                    # if(kpi_pending_actions.objects.filter(kpi_id=i["id"], action="alert",user_id=userid, delete_flag='N')):
                                        
                            else:
                                check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(first_day_of_month(today).strftime("%Y-%m-%d"))).values()
                                if len(check_exist_actual) == 0 and (last_day_of_month(today) - today).days <= 7:
                                    data = {
                                        'user_id' : userid,
                                        'kpi' : i['kpi_code'],
                                        'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(first_day_of_month(today+timedelta(days=30)).strftime("%Y-%m-%d")),
                                        'upcoming_date':str(first_day_of_month(today+timedelta(days=30)).strftime("%Y-%m-%d")),
                                        'kpi_id':i["id"],
                                        'action': "alert",
                                        'created_by' : userid,
                                        'last_updated_by':userid
                                    }
                                    if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0):
                                        kpi_serializer = kpi_pending_actions_serializer(data=data)
                                        if(kpi_serializer.is_valid()):
                                            kpi_serializer.save()
                                    else:
                                        json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                        item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                        serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                        if serializer.is_valid():
                                            serializer.save()
                if freq.strip() == 'Weekly':
                    if kpi_created_date >= from_date and kpi_created_date <= to_date:
                        last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                        currect_date = to_date+timedelta(days=1) if (to_date > today) == False else today+timedelta(days=1)
                        last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                        pending_actuals = (datetime.datetime.strptime(currect_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date() - datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date()).days
                        if (to_date > today) == True:
                            check_exist_actual = ''
                            if(i['period_type'].strip() == 'End'):
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(last_day_of_week(today).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0:
                                data = {
                                    'user_id' : userid,
                                    'kpi' : i['kpi_code'],
                                    'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(last_day_of_week(today).strftime("%Y-%m-%d")),
                                    'upcoming_date':str(last_day_of_week(today).strftime("%Y-%m-%d")),
                                    'kpi_id':i["id"],
                                    'action': "alert",
                                    'created_by' : userid,
                                    'last_updated_by':userid
                                }
                                if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0 ):
                                    kpi_serializer = kpi_pending_actions_serializer(data=data)
                                    if(kpi_serializer.is_valid()):
                                        kpi_serializer.save()
                                else:
                                    json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                    item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                    serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                    if serializer.is_valid():
                                        serializer.save()
                            else:
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(first_day_of_week(today).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0:
                                data = {
                                    'user_id' : userid,
                                    'kpi' : i['kpi_code'],
                                    'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(first_day_of_week(today+timedelta(days=7)).strftime("%Y-%m-%d")),
                                    'upcoming_date':str(first_day_of_week(today+timedelta(days=7)).strftime("%Y-%m-%d")),
                                    'kpi_id':i["id"],
                                    'action': "alert",
                                    'created_by' : userid,
                                    'last_updated_by':userid
                                }
                                if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0 ):
                                    kpi_serializer = kpi_pending_actions_serializer(data=data)
                                    if(kpi_serializer.is_valid()):
                                        print("enter 12")
                                        kpi_serializer.save()
                                else:
                                    json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                    item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                    serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                    if serializer.is_valid():
                                        serializer.save()
                if freq.strip() == 'Quarterly':
                    if kpi_created_date >= from_date and kpi_created_date <= to_date:
                        last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                        currect_date = to_date+timedelta(days=1) if (to_date > today) == False else today+timedelta(days=1)
                        last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                        pending_actuals = (datetime.datetime.strptime(currect_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date() - datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date()).days
                        if (to_date > today) == True:
                            check_exist_actual = ''
                            if(i['period_type'].strip() == 'End'):
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(get_last_day_of_the_quarter(today.day, today.month, today.year).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0:
                                data = {
                                    'user_id' : userid,
                                    'kpi' : i['kpi_code'],
                                    'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(get_last_day_of_the_quarter(today.day, today.month, today.year).strftime("%Y-%m-%d")),
                                    'upcoming_date':str(get_last_day_of_the_quarter(today.day, today.month, today.year).strftime("%Y-%m-%d")),
                                    'kpi_id':i["id"],
                                    'action': "alert",
                                    'created_by' : userid,
                                    'last_updated_by':userid
                                }
                                # print("data end", data)
                                if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0 ):
                                    kpi_serializer = kpi_pending_actions_serializer(data=data)
                                    if(kpi_serializer.is_valid()):
                                        kpi_serializer.save()
                                else:
                                    json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                    item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                    serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                    if serializer.is_valid():
                                        serializer.save()
                            else:
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(get_first_day_of_the_next_quarter(today.day, today.month, today.year).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0:
                                data = {
                                    'user_id' : userid,
                                    'kpi' : i['kpi_code'],
                                    'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(get_first_day_of_the_next_quarter(today.day, today.month+3, today.year).strftime("%Y-%m-%d")),
                                    'upcoming_date':str(get_first_day_of_the_next_quarter(today.day, today.month+3, today.year).strftime("%Y-%m-%d")),
                                    'kpi_id':i["id"],
                                    'action': "alert",
                                    'created_by' : userid,
                                    'last_updated_by':userid
                                }
                                if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0 ):
                                    kpi_serializer = kpi_pending_actions_serializer(data=data)
                                    if(kpi_serializer.is_valid()):
                                        kpi_serializer.save()
                                else:
                                    json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                    item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                    serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                    if serializer.is_valid():
                                        serializer.save()
                if freq.strip() == 'Half-yearly':
                    if kpi_created_date >= from_date and kpi_created_date <= to_date:
                        last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                        currect_date = to_date+timedelta(days=1) if (to_date > today) == False else today+timedelta(days=1)
                        pending_actuals = (datetime.datetime.strptime(currect_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date() - datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date()).days
                        if (to_date > today) == True:
                            check_exist_actual = ''
                            if(i['period_type'].strip() == 'End'):
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(get_last_day_of_the_quarter(today.day, today.month, today.year).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0:
                                data = {
                                    'user_id' : userid,
                                    'kpi' : i['kpi_code'],
                                    'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(get_last_day_of_the_half_yearly(today.day, today.month, today.year).strftime("%Y-%m-%d")),
                                    'upcoming_date':str(get_last_day_of_the_half_yearly(today.day, today.month, today.year).strftime("%Y-%m-%d")),
                                    'kpi_id':i["id"],
                                    'action': "alert",
                                    'created_by' : userid,
                                    'last_updated_by':userid
                                }
                                if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0 ):
                                    kpi_serializer = kpi_pending_actions_serializer(data=data)
                                    if(kpi_serializer.is_valid()):
                                        kpi_serializer.save()
                                else:
                                    json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                    item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                    serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                    if serializer.is_valid():
                                        serializer.save()
                            else:
                                # check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(get_first_day_of_the_next_half_yearly(today.day, today.month, today.year).strftime("%Y-%m-%d"))).values()
                                # if len(check_exist_actual) == 0:
                                data = {
                                    'user_id' : userid,
                                    'kpi' : i['kpi_code'],
                                    'message' : i['kpi_code']+' is scheduled for its '+i['frequency']+' update, and the next due date is '+str(get_first_day_of_the_next_half_yearly(today.day, today.month, today.year).strftime("%Y-%m-%d")),
                                    'upcoming_date':str(get_first_day_of_the_next_half_yearly(today.day, today.month, today.year).strftime("%Y-%m-%d")),
                                    'kpi_id':i["id"],
                                    'action': "alert",
                                    'created_by' : userid,
                                    'last_updated_by':userid
                                }
                                if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values()) == 0 ):
                                    kpi_serializer = kpi_pending_actions_serializer(data=data)
                                    if(kpi_serializer.is_valid()):
                                        kpi_serializer.save()
                                else:
                                    json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="alert", delete_flag='N').values("id")
                                    item = kpi_pending_actions.objects.get(id=json[0]["id"])
                                    serializer = kpi_pending_actions_serializer(instance=item, data=data)
                                    if serializer.is_valid():
                                        serializer.save()
    print("Kpi Remainder scheduler is running completed")



def check_kpi_actulas_pending():
    kpi_pending = kpi_pending_actions.objects.all()
    kpi_user = kpi_user_access.objects.filter(delete_flag='N')
    kpi_user_serializer = kpi_user_Access_serializer(kpi_user, many=True)
    today = datetime.datetime.today()
    for user in kpi_user_serializer.data:
        userid = user.pop('user_id')
        kpiid = user.pop('kpi_id')
        kpi = kpi_details.objects.filter(delete_flag='N', id=kpiid).values()
        for i in kpi:
            sc_from_to_date = scorecard.objects.filter(delete_flag='N', id=i['scorecard_id_id']).values()
            if(len(sc_from_to_date) == 1):
                from_date = sc_from_to_date[0]['from_date']
                to_date = sc_from_to_date[0]['to_date']
                # check_to_date_year = 
                kpi_created_date = i['created_date'] if i['created_date'] != '' else ''
                freq = kpi = c_date = cr_date = kpi_date = todate_fromdate = ''
                kpi = i['kpi_code'] if i['kpi_code'] != '' else ''
                freq = i['frequency'] if i['frequency'] != '' else ''
                today_k = today.strftime("%Y-%m-%d")
                kpiActuals = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id']).values()
                # print("kpiActuals", len(kpiActuals))
                # print("kpiActuals last----", kpiActuals.last())
                # today_k = to_date.strftime("%Y-%m-%d") > today.strftime("%Y-%m-%d") if today.strftime("%Y-%m-%d") else to_date.strftime("%Y-%m-%d")
                # print("to_date", to_date)
                # print(relativedelta.relativedelta(datetime.datetime.strptime("2023-12-31", "%Y-%m-%d"), datetime.datetime.strptime("2022-02-01", "%Y-%m-%d")).months)
                # if freq.strip() == 'Monthly':
                    # Pending Section
                if kpi_created_date >= from_date and kpi_created_date <= to_date:
                    currect_date = to_date+timedelta(days=1) if (to_date > today) == False else today+timedelta(days=1)
                    count_from_to_btwn = relativedelta.relativedelta(to_date, from_date).months
                    # last_actual_date = (from_date-timedelta(days=1)) if len(kpiActuals) == 0 else kpiActuals.last()['period']
                    last_actual_date = from_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                    count_no_of_pending_actuals = relativedelta.relativedelta(datetime.datetime.strptime(currect_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date(), datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date())
                    pending_actuals = int(0)
                    if freq.strip() == 'Monthly':
                        pending_actuals = count_no_of_pending_actuals.months + (12*count_no_of_pending_actuals.years)
                    if freq.strip() == 'Daily':
                        pending_actuals = (datetime.datetime.strptime(currect_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date() - datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date()).days
                    if freq.strip() == 'Weekly':
                        pending_actuals = (datetime.datetime.strptime(currect_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date() - datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date()).days / 7
                    if freq.strip() == 'Quarterly':
                        pending_actuals = (count_no_of_pending_actuals.months + (12*count_no_of_pending_actuals.years)) / 3
                    if freq.strip() == 'Half-yearly':
                        pending_actuals = (count_no_of_pending_actuals.months + (12*count_no_of_pending_actuals.years)) / 6
                    if freq.strip() == 'Annualy':
                        pending_actuals = (count_no_of_pending_actuals.months + (12*count_no_of_pending_actuals.years)) / 12
                    if round(pending_actuals) > 0:
                        data = {
                            'user_id' : userid,
                            'kpi' : i['kpi_code'],
                            'message' : i['kpi_code']+' currently has '+str(round(pending_actuals))+' pending actuals.',
                            # 'upcoming_date':'0000-00-00',
                            # 'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                            'kpi_id':i["id"],
                            'action': "pending",
                            'created_by' : userid,
                            'last_updated_by':userid
                        }
                        if (len(kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="pending", delete_flag='N').values()) == 0 ):
                            kpi_serializer = kpi_pending_actions_serializer(data=data)
                            if(kpi_serializer.is_valid()):
                                kpi_serializer.save()
                        else:
                            json=kpi_pending_actions.objects.filter(kpi_id=i["id"],user_id=userid, action="pending", delete_flag='N').values("id")
                            item = kpi_pending_actions.objects.get(id=json[0]["id"])
                            serializer = kpi_pending_actions_serializer(instance=item, data=data)
                            if serializer.is_valid():
                                serializer.save()
                    else:
                        kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid, delete_flag='N').delete()
                        # print("change delete_flag for existing entry in pendings table")
                    # Remainder section
                        # if (to_date > today) == True:
                        #     if(i['period_type'].strip() == 'End'):
                        #         check_exist_actual = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'], period=str(last_day_of_month(last_actual_date).strftime("%Y-%m-%d"))).values()
                        #         print(last_day_of_month(last_actual_date).strftime("%Y-%m-%d"), check_exist_actual)
                                # print(i['kpi_code'], datetime.datetime.strptime(from_date.strftime("%Y-%m-%d"), "%Y-%m-%d").)
                    # else:
                    #     # print("today greater then today", today, kpi_created_date)
                    #     if i['period_type'].strip() == 'End':
                    #         count_from_to_btwn = relativedelta.relativedelta(today, kpi_created_date).months
                    #         print("count_from_to_btwn", count_from_to_btwn)
                    #         last_actual_date = kpi_created_date if len(kpiActuals) == 0 else kpiActuals.last()['period']
                    #         print("last_actual_date", last_actual_date)
                    #         count_no_of_pending_actuals = relativedelta.relativedelta(datetime.datetime.strptime(to_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date(), datetime.datetime.strptime(last_actual_date.strftime("%Y-%m-%d"), "%Y-%m-%d").date()).months
                    #         if count_no_of_pending_actuals > 0:
                    #             data = {
                    #                 'user_id' : userid,
                    #                 'kpi' : i['kpi_code'],
                    #                 'message' : i['kpi_code']+' having '+str(count_no_of_pending_actuals)+' pending actuals.',
                    #                 'upcoming_date':'',
                    #                 # 'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #                 'kpi_id':i["id"],
                    #                 'action': "pending",
                    #                 'created_by' : userid,
                    #                 'last_updated_by':userid
                    #             }
                                # print("data", data)
                # if freq.strip() == 'Monthly':
                # if(i['period_type'].strip() == 'End'):
                #     print("end")
                # else:
                #     if kpi_created_date >= from_date and kpi_created_date <= to_date:
                #         print("---1", i['id'], from_date, to_date, kpi_created_date)
                #         kpiActuals = kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id']).values().last()
                #         day = int(kpi_created_date.strftime("%d"))
                #         month = int(kpi_created_date.strftime("%m"))
                #         year = int(kpi_created_date.strftime("%Y"))
                #         # print("kpi---", kpi, freq, from_date, to_date, kpi_created_date, "today--", today, day, month, year)
                #         # print("i['period_type']", i['period_type'])
                #         kpi_day = kpi_created_date.strftime("%Y-%m-%d")
                    # if(freq.strip() == 'Daily'):
                    #     if(i['period_type'].strip() == 'End'):
                    #         chsj = kpi_day
                    #     else: 
                    #         chsj = kpi_created_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=1)
                    #     pending_insert = False
                    #     if kpiActuals != None:
                    #         if(str(kpiActuals['period']+timedelta(days=1)) <= today_k):
                    #             pending_insert = True
                    #     else:
                    #         if str(chsj) <= today_k:
                    #             pending_insert = True
                    #     if pending_insert:
                    #         data = {
                    #             'user_id' : userid,
                    #             'kpi' : i['kpi_code'],
                    #             'message' : i['kpi_code']+' is pending',
                    #             'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #             'kpi_id':i["id"],
                    #             "action": "pending",
                    #             'created_by' : userid,
                    #             'last_updated_by':userid
                    #         }
                            # if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                            #     kpi_serializer = kpi_pending_actions_serializer(data=data)
                            #     if(kpi_serializer.is_valid()):
                            #         kpi_serializer.save()
                            # if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                            #     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                            #     item = kpi_pending_actions.objects.get(id=json[0]["id"])
                            #     serializer = kpi_pending_actions_serializer(instance=item, data=data)
                            #     if serializer.is_valid():
                            #         serializer.save()

                    # if(freq.strip() == 'Weekly'):
                    #     if(i['period_type'] == 'End'):
                    #         chsj = kpi_day
                    #     else: 
                    #         chsj = kpi_created_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=7)
                    #     pending_insert = False
                    #     if kpiActuals != None:
                    #         if(str(kpiActuals['period']+timedelta(days=7)) <= today_k):
                    #             pending_insert = True
                    #     else:
                    #         if str(chsj) <= today_k:
                    #             pending_insert = True
                    #     if pending_insert:
                    #         data = {
                    #             'user_id' : userid,
                    #             'kpi' : i['kpi_code'],
                    #             'message' : i['kpi_code']+' is pending',
                    #             'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #             'kpi_id':i["id"],
                    #             'action': "pending",
                    #             'created_by' : userid,
                    #             'last_updated_by':userid
                    #         }
                    #         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #             kpi_serializer = kpi_pending_actions_serializer(data=data)
                    #             if(kpi_serializer.is_valid()):
                    #                 kpi_serializer.save()
                    #         # if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #         #     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                    #         #     item = kpi_pending_actions.objects.get(id=json[0]["id"])
                    #         #     serializer = kpi_pending_actions_serializer(instance=item, data=data)
                    #         #     if serializer.is_valid():
                    #         #         serializer.save()

                    # if(freq.strip() == 'Monthly'):
                    #     if(i['period_type'].strip() == 'End'):
                    #         chsj = last_day_of_month(datetime.date(year, month, day))
                    #     else: 
                    #         chsj = last_day_of_month(datetime.date(year, month, day))+timedelta(days=1)
                    #     pending_insert = False
                    #     if kpiActuals != None:
                    #         # todate_fromdate = (to_date - from_date).days
                    #         # print("to_date", to_date, "from_date", from_date)
                    #         # todate_fromdate = relativedelta.relativedelta(to_date, from_date).months + 1
                    #         # print("todate_fromdate", todate_fromdate, type(todate_fromdate))
                    #         if to_date < datetime.datetime.strptime(today_k, "%Y-%m-%d"):
                    #             todate_fromdate = relativedelta.relativedelta(to_date, from_date).months + 1
                    #         else:
                    #             todate_fromdate = relativedelta.relativedelta(datetime.datetime.strptime(today_k, "%Y-%m-%d"), from_date).months + 1
                    #         # print("todate_fromdate", todate_fromdate)
                    #         # print(i['id'], len(kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'])))
                    #         print(type(str(todate_fromdate-len(kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'])))))
                    #         get_btwn_today_actualdate = (datetime.datetime.strptime(today_k, "%Y-%m-%d").date()-kpiActuals['period']).days
                    #         if(str(kpiActuals['period']+timedelta(days=31)) <= today_k):
                    #             pending_insert = True
                    #     else:
                    #         if str(chsj) <= today_k:
                    #             pending_insert = True
                    #     if pending_insert:
                    #         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #             data = {
                    #                 'user_id' : userid,
                    #                 'kpi' : i['kpi_code'],
                    #                 # 'message' : i['kpi_code']+' is '+str(todate_fromdate-len(kpi_actuals.objects.filter(delete_flag='N', kpi_id=i['id'])))+' pending.',
                    #                 'message' : i['kpi_code']+' is pending.',
                    #                 # 'upcoming_date': kpi_day,
                    #                 'upcoming_date': kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #                 'kpi_id':i["id"],
                    #                 "action": "pending",
                    #                 'created_by' : userid,
                    #                 'last_updated_by':userid
                    #             }
                    #             kpi_serializer = kpi_pending_actions_serializer(data=data)
                    #             if(kpi_serializer.is_valid()):
                    #                 kpi_serializer.save()
                            # if (kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                            #     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                            #     item = kpi_pending_actions.objects.get(id=json[0]["id"])
                            #     serializer = kpi_pending_actions_serializer(instance=item, data=data)
                            #     if serializer.is_valid():
                            #         # print("success----", serializer.data)
                            #         serializer.save()
                    # if(freq.strip() == 'Quarterly'):
                    #     if(i['period_type'] == 'End'):
                    #         chsj = get_last_day_of_the_quarter(day,month,year)
                    #     else: 
                    #         # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + relativedelta(years=1) -timedelta(days=4)
                    #         # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=12, day=31)-timedelta(days=5)
                    #         chsj = get_first_day_of_the_next_quarter(day,month,year)
                    #     pending_insert = False
                    #     if kpiActuals != None:
                    #         if(str(kpiActuals['period']+timedelta(months=3)) <= today_k):
                    #             pending_insert = True
                    #     else:
                    #         if str(chsj) <= today_k:
                    #             pending_insert = True
                    #     if pending_insert:
                    #         data = {
                    #             'user_id' : userid,
                    #             'kpi' : i['kpi_code'],
                    #             'message' : i['kpi_code']+' is pending',
                    #             'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #             'kpi_id':i["id"],
                    #             'action': "pending",
                    #             'created_by' : userid,
                    #             'last_updated_by':userid
                    #         }
                    #         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #             kpi_serializer = kpi_pending_actions_serializer(data=data)
                    #             if(kpi_serializer.is_valid()):
                    #                 kpi_serializer.save()
                            # if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                            #     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                            #     item = kpi_pending_actions.objects.get(id=json[0]["id"])
                            #     serializer = kpi_pending_actions_serializer(instance=item, data=data)
                            #     if serializer.is_valid():
                            #         serializer.save()

                    # if(freq.strip() == 'Half-yearly'):
                    #     if(i['period_type'] == 'End'):
                    #         chsj = get_last_day_of_the_half_yearly(day,month,year)
                    #     else:
                    #         chsj = get_first_day_of_the_next_half_yearly(day,month,year)
                    #     pending_insert = False
                    #     if kpiActuals != None:
                    #         if(str(kpiActuals['period']+timedelta(months=6)) <= today_k):
                    #             pending_insert = True
                    #     else:
                    #         if str(chsj) <= today_k:
                    #             pending_insert = True
                    #     if pending_insert:
                    #         data = {
                    #             'user_id' : userid,
                    #             'kpi' : i['kpi_code'],
                    #             'message' : i['kpi_code']+' is pending',
                    #             'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #             'kpi_id':i["id"],
                    #             'action': "pending",
                    #             'created_by' : userid,
                    #             'last_updated_by':userid
                    #         }
                    #         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #             kpi_serializer = kpi_pending_actions_serializer(data=data)
                    #             if(kpi_serializer.is_valid()):
                    #                 kpi_serializer.save()
                            # if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                            #     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                            #     item = kpi_pending_actions.objects.get(id=json[0]["id"])
                            #     serializer = kpi_pending_actions_serializer(instance=item, data=data)
                            #     if serializer.is_valid():
                            #         serializer.save()

                    # if(freq.strip() == 'Annualy'):
                    #     kpi_day = kpi_date.strftime("%Y-%m-%d")
                    #     kpi_year = int(kpi_date.strftime("%Y"))
                    #     today_k = today.strftime("%Y-%m-%d")
                    #     if(i['period_type'] == 'End'):
                    #         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=12, day=31)-timedelta(days=5)
                    #     else: 
                    #         # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + relativedelta(years=1) -timedelta(days=4)
                    #         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=1, day=1, year=year+1)-timedelta(days=5)
                    #     pending_insert = False
                    #     if kpiActuals != None:
                    #         if(str(kpiActuals['period']+timedelta(months=12)) <= today_k):
                    #             pending_insert = True
                    #     else:
                    #         if str(chsj) <= today_k:
                    #             pending_insert = True
                    #     if pending_insert:
                    #         data = {
                    #             'user_id' : userid,
                    #             'kpi' : i['kpi_code'],
                    #             'message' : i['kpi_code']+' is pending',
                    #             'upcoming_date':kpi_created_date.strptime(kpi_day,"%Y-%m-%d"),
                    #             'kpi_id':i["id"],
                    #             'action': "pending",
                    #             'created_by' : userid,
                    #             'last_updated_by':userid
                    #         }
                    #         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #             kpi_serializer = kpi_pending_actions_serializer(data=data)
                    #             if(kpi_serializer.is_valid()):
                    #                 kpi_serializer.save()
                            # if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                            #     json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                            #     item = kpi_pending_actions.objects.get(id=json[0]["id"])
                            #     serializer = kpi_pending_actions_serializer(instance=item, data=data)
                            #     if serializer.is_valid():
                            #         serializer.save()

            # if(key == 'frequency' or key == 'created_date'):
            #     if(key == 'frequency'):
            #         freq = value
            #     else:
            #         for fmt in ('%Y-%m-%dT%H:%M:%S','%Y-%m-%d', '%d.%m.%Y', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f'):
        #                     try:
        #                         try:
        #                             kpi_date = datetime.datetime.strptime(value, fmt)
        #                             cr_date = kpi_date.strftime("%Y-%m-%d %H:%M:%S")
        #                             break
        #                         except:
        #                             continue
        #                     except ValueError:
        #                         print("error: no valid date format found")
        #                         pass
        #                         raise ValueError('no valid date format found')
        #                 kpi_day = kpi_date.strftime("%Y-%m-%d")
        #                 today_k = today.strftime("%Y-%m-%d")
        #                 day = int(kpi_date.strftime("%d"))
        #                 month = int(kpi_date.strftime("%m"))
        #                 year = int(kpi_date.strftime("%Y"))
        #                 kpi_year = int(kpi_date.strftime("%Y"))
        # #                 if(freq.strip() == 'Daily'):
        # #                     if(i['period_type'] == 'End'):
        # #                         chsj = kpi_day
        # #                     else: 
        # #                         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=1)
        # #                     if(str(chsj) <= today_k):
        # #                         data = {
        # #                             'user_id' : userid,
        # #                             'kpi' : i['kpi_code'],
        # #                             'message' : i['kpi_code']+' is pending',
        # #                             'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
        # #                             'kpi_id':i["id"],
        # #                             'created_by' : userid,
        # #                             'last_updated_by':userid
        # #                         }
        # #                         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        # #                             kpi_serializer = kpi_pending_actions_serializer(data=data)
        # #                             if(kpi_serializer.is_valid()):
        # #                                 kpi_serializer.save()
        # #                         if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        # #                             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
        # #                             item = kpi_pending_actions.objects.get(id=json[0]["id"])
        # #                             serializer = kpi_pending_actions_serializer(instance=item, data=data)
        # #                             if serializer.is_valid():
        # #                                 serializer.save()
                                
                                    
        # #                 if(freq.strip() == 'Weekly'):
        # #                     if(i['period_type'] == 'End'):
        # #                         chsj = kpi_day
        # #                     else: 
        # #                         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=7)
                            
        # #                     if(str(chsj) <= today_k):
        # #                         data = {
        # #                             'user_id' : userid,
        # #                             'kpi' : i['kpi_code'],
        # #                             'message' : i['kpi_code']+' is pending',
        # #                             'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
        # #                             'kpi_id':i["id"],
        # #                             'created_by' : userid,
        # #                             'last_updated_by':userid
        # #                         }
        # #                         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        # #                             kpi_serializer = kpi_pending_actions_serializer(data=data)
        # #                             if(kpi_serializer.is_valid()):
        # #                                 kpi_serializer.save()
        # #                         if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        # #                             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
        # #                             item = kpi_pending_actions.objects.get(id=json[0]["id"])
        # #                             serializer = kpi_pending_actions_serializer(instance=item, data=data)
        # #                             if serializer.is_valid():
        # #                                 serializer.save()
                        
        # #                 if(freq.strip() == 'Fortnightly'):
        # #                     if(i['period_type'] == 'End'):
        # #                         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=14)
        # #                     else: 
        # #                         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=15)
        # #                     if(str(chsj) <= today_k):
        # #                         data = {
        # #                             'user_id' : userid,
        # #                             'kpi' : i['kpi_code'],
        # #                             'message' : i['kpi_code']+' is pending',
        # #                             'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
        # #                             'kpi_id':i["id"],
        # #                             'created_by' : userid,
        # #                             'last_updated_by':userid
        # #                         }
        # #                         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        # #                             kpi_serializer = kpi_pending_actions_serializer(data=data)
        # #                             if(kpi_serializer.is_valid()):
        # #                                 kpi_serializer.save()
        # #                         if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        # #                             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
        # #                             item = kpi_pending_actions.objects.get(id=json[0]["id"])
        # #                             serializer = kpi_pending_actions_serializer(instance=item, data=data)
        # #                             if serializer.is_valid():
        # #                                 serializer.save()

                        # if(freq.strip() == 'Monthly'):
                        #     if(i['period_type'] == 'End'):
                        #         chsj = last_day_of_month(datetime.date(year, month, day))
                        #     else: 
                        #         chsj = last_day_of_month(datetime.date(year, month, day))+timedelta(days=1)
                        #     if(str(chsj) <= today_k):
                        #         data = {
                        #             'user_id' : userid,
                        #             'kpi' : i['kpi_code'],
                        #             'message' : i['kpi_code']+' is pending',
                        #             'upcoming_date': kpi_date.strptime(kpi_day,"%Y-%m-%d"),
                        #             'kpi_id':i["id"],
                        #             'created_by' : userid,
                        #             'last_updated_by':userid
                        #         }

                        #         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                        #             kpi_serializer = kpi_pending_actions_serializer(data=data)
                        #             if(kpi_serializer.is_valid()):
                        #                 kpi_serializer.save()
                        #         if (kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                        #             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
                        #             item = kpi_pending_actions.objects.get(id=json[0]["id"])
                        #             serializer = kpi_pending_actions_serializer(instance=item, data=data)
                        #             if serializer.is_valid():
                        #                 serializer.save()

        #                 if(freq.strip() == 'Quarterly'):
        #                     if(i['period_type'] == 'End'):
        #                         chsj = get_last_day_of_the_quarter(day,month,year)
        #                     else: 
        #                         # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + relativedelta(years=1) -timedelta(days=4)
        #                         # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=12, day=31)-timedelta(days=5)
        #                         chsj = get_first_day_of_the_next_quarter(day,month,year)
        #                     if(str(chsj) <= today_k):
        #                         data = {
        #                             'user_id' : userid,
        #                             'kpi' : i['kpi_code'],
        #                             'message' : i['kpi_code']+' is pending',
        #                             'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
        #                             'kpi_id':i["id"],
        #                             'created_by' : userid,
        #                             'last_updated_by':userid
        #                         }
        #                         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        #                             kpi_serializer = kpi_pending_actions_serializer(data=data)
        #                             if(kpi_serializer.is_valid()):
        #                                 kpi_serializer.save()
        #                         if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        #                             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
        #                             item = kpi_pending_actions.objects.get(id=json[0]["id"])
        #                             serializer = kpi_pending_actions_serializer(instance=item, data=data)
        #                             if serializer.is_valid():
        #                                 serializer.save()

        #                 if(freq.strip() == 'Half-yearly'):
        #                     if(i['period_type'] == 'End'):
        #                         chsj = get_last_day_of_the_half_yearly(day,month,year)
        #                     else:
        #                         chsj = get_first_day_of_the_next_half_yearly(day,8,year)
                                
        #                     if(str(chsj) <= today_k):
        #                         data = {
        #                             'user_id' : userid,
        #                             'kpi' : i['kpi_code'],
        #                             'message' : i['kpi_code']+' is pending',
        #                             'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
        #                             'kpi_id':i["id"],
        #                             'created_by' : userid,
        #                             'last_updated_by':userid
        #                         }
        #                         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        #                             kpi_serializer = kpi_pending_actions_serializer(data=data)
        #                             if(kpi_serializer.is_valid()):
        #                                 kpi_serializer.save()
        #                         if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        #                             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
        #                             item = kpi_pending_actions.objects.get(id=json[0]["id"])
        #                             serializer = kpi_pending_actions_serializer(instance=item, data=data)
        #                             if serializer.is_valid():
        #                                 serializer.save()

        #                 if(freq.strip() == 'Annualy'):
        #                     kpi_day = kpi_date.strftime("%Y-%m-%d")
        #                     kpi_year = int(kpi_date.strftime("%Y"))
        #                     today_k = today.strftime("%Y-%m-%d")
        #                     if(i['period_type'] == 'End'):
        #                         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=12, day=31)-timedelta(days=5)
        #                     else: 
        #                         # chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + relativedelta(years=1) -timedelta(days=4)
        #                         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d").replace(month=1, day=1, year=year+1)-timedelta(days=5)
        #                     if(str(chsj) <= today_k):
                                
        #                         data = {
        #                             'user_id' : userid,
        #                             'kpi' : i['kpi_code'],
        #                             'message' : i['kpi_code']+' is pending',
        #                             'upcoming_date':kpi_date.strptime(kpi_day,"%Y-%m-%d"),
        #                             'kpi_id':i["id"],
        #                             'created_by' : userid,
        #                             'last_updated_by':userid
        #                         }
        #                         if (not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        #                             kpi_serializer = kpi_pending_actions_serializer(data=data)
        #                             if(kpi_serializer.is_valid()):
        #                                 kpi_serializer.save()
        #                         if(kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
        #                             json=kpi_pending.filter(kpi=i['kpi_code'].strip()).values("id")
        #                             item = kpi_pending_actions.objects.get(id=json[0]["id"])
        #                             serializer = kpi_pending_actions_serializer(instance=item, data=data)
        #                             if serializer.is_valid():
        #                                 serializer.save()





                    # if(freq.strip() == 'Quarterly'):
                    #     kpi_day = kpi_date.strftime("%Y-%m-%d")
                    #     today_k = today.strftime("%Y-%m-%d")
                    #     if(i['period_type'] == 'End'):
                    #         chsj = kpi_day
                    #     else: 
                    #         chsj = kpi_date.strptime(kpi_day,"%Y-%m-%d") + timedelta(days=7)
                    #     # print(chsj)
                    #     if(str(chsj) <= today_k):
                    #         data = {
                    #             'user_id' : userid,
                    #             'kpi' : i['kpi_code'],
                    #             'message' : i['kpi_code']+' is pending',
                    #             'created_by' : userid,
                    #             'last_updated_by':userid
                    #         }
                    #         # print(kpi_pending.filter(kpi=i['kpi_code']))
                    #         kpi_serializer = kpi_pending_actions_serializer(data=data)
                    #         if (kpi_serializer.is_valid() and not kpi_pending.filter(kpi=i['kpi_code'].strip(),user_id=userid)):
                    #             print(data)
                    #             # kpi_serializer.save()
    print("Kpi pending scheduler is running completed")

#---------------------End Old Fun ---------------------------



        # kpiid = kpiData.pop('id')
        # kpiActuals = kpi_actuals.objects.filter(delete_flag='N', kpi_id=kpiid)
        # kpiActualsSer =kpi_actuals_serializer(kpiActuals, many=True)
        # for actualsData in kpiActualsSer.data:
        #     print(f"==>> actualsData: {actualsData}")

# check_kpi_actulas()
# while True:
#     schedule.run_pending()
#     time.sleep(1)


# To get all Tables in django db
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_tables(request):
    table_names = []

    if apps.get_app_config("base").get_models():
        for model in apps.get_app_config("base").get_models():
            table = model._meta.db_table

            table_names.append(table)

        return Response(table_names, status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


# To get model,serializers,fields in django db using respective table_name


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_dynamic_trio(request, tablename):
    if tablename:
        model_name = tablename.replace("tb_sc_", "")
        serializer_name = model_name + "_serializer"

        model_obj = apps.get_model("base", model_name)

        table_fields = []
        non_required_fields = [
            "created_by",
            "last_updated_by",
            "last_updated_date",
            "delete_flag",
        ]

        for field in model_obj._meta.fields:
            table_fields.append(field.name)

        # To remove and return the mentioned fields in non_required_fields
        for i in non_required_fields:
            if table_fields.index(i):
                table_fields.remove(i)

        return Response(
            {
                "model_name": model_name,
                "serializer_name": serializer_name,
                "table_fields": table_fields,
            },
            status=status.HTTP_200_OK,
        )

    else:
        return Response(status=status.HTTP_404_NOT_FOUND)


# To perform dynamic filtering for dynamically selected table (single table)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def get_dynamic_filtering(request):
    sample = request.data
    # print(sample)
    for key, val in sample.items():
        if key == "model_name_query":
            model_name_list = val
        if key == "serializer_name_query":
            serializer_name_list = val
        if key == "table_columns_query":
            choose_multi_column_list = val
        if key == "col_name":
            conditional_column_lists = val
        if key == "conditional_operator":
            conditional_operator_lists = val
        if key == "col_value":
            value_lists = val
        if key == "from_date_value":
            from_date_lists = val
        if key == "to_date_value":
            to_date_lists = val

    range_list_col = []
    range_list_ope = []
    non_range_list_col = []
    non_range_list_ope = []

    unique_model_data_list = []

    for i in range(len(conditional_operator_lists)):
        if conditional_operator_lists[i] == "__range":
            range_list_col.append(conditional_column_lists[i])
            range_list_ope.append(conditional_operator_lists[i])
        if conditional_operator_lists[i] != "__range":
            non_range_list_col.append(conditional_column_lists[i])
            non_range_list_ope.append(conditional_operator_lists[i])

    from_date_type_list = []
    to_date_type_list = []

    for i in range(len(from_date_lists)):
        from_date_type_list.append(
            datetime.datetime.strptime(from_date_lists[i], "%Y-%m-%d").date()
        )
        to_date_type_list.append(
            datetime.datetime.strptime(to_date_lists[i], "%Y-%m-%d").date() + timedelta(days=1)
        )

    model = apps.get_model("base", *model_name_list)

    serializer_obj = {
        "org_definition_serializer": org_definition_serializer,
        "org_functional_level_serializer": org_functional_level_serializer,
        "currencies_serializer": currencies_serializer,
        "org_settings_serializer": org_settings_serializer,
        "org_functional_hierarchy_serializer": org_functional_hierarchy_serializer,
        "navigation_menu_details_serializer": navigation_menu_details_serializer,
        "user_access_definition_serializer": user_access_definition_serializer,
        "config_codes_serializer": config_codes_serializer,
        "uom_serializer": uom_serializer,
        "user_serializer": user_serializer,
        "user_user_access_serializer": user_user_access_serializer,
        "perspectives_serializer": perspectives_serializer,
        "scorecard_serializer": scorecard_serializer,
        "scorecard_details_serializer": scorecard_details_serializer,
        "business_goals_objectives_serializer": business_goals_objectives_serializer,
        "kpi_details_serializer": kpi_details_serializer,
        "kpi_actuals_serializer": kpi_actuals_serializer,
    }

    if sample:
        # Non-Date Range Filter set START
        col_op_val_list = []
        for i in range(len(value_lists)):
            col_op_val_list.append(
                {non_range_list_col[i] + non_range_list_ope[i]: value_lists[i]}
            )

        q_set = []
        for i in range(len(col_op_val_list)):
            q_set.append(list(chain(model.objects.filter(**col_op_val_list[i]))))

        # flattening nested list queryset to single list of queryset
        new_q_set = list(chain(*q_set))

        for i in new_q_set:
            unique_model_data_list.append(i)
        # END

        # Date Range Filter set START
        col_op_val_list2 = []
        for i in range(len(from_date_type_list)):
            col_op_val_list2.append(
                {
                    range_list_col[i]
                    + range_list_ope[i]: [from_date_type_list[i], to_date_type_list[i]]
                }
            )

        q_set2 = []
        for i in range(len(col_op_val_list2)):
            q_set2.append(list(chain(model.objects.filter(**col_op_val_list2[i]))))

        # flattening nested list queryset to single list of queryset
        new_q_set2 = list(chain(*q_set2))

        for i in new_q_set2:
            unique_model_data_list.append(i)
        # END

        # convert list to set to get unique values alone has a dataset
        unique_model_data_set = set(unique_model_data_list)

        # convert the set to the list
        new_unique_model_data_list = list(unique_model_data_set)

        dynamic_serializer = serializer_obj[serializer_name_list[0]](
            new_unique_model_data_list, many=True
        )
        return Response(dynamic_serializer.data, status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


# Kpi_sli Insert
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_kpi_sli(request):
    list_data = request.data
    for i in range(len(list_data)):
        data = {
            "kpi_id": list_data[i]["kpi_id"],
            "sli_from": list_data[i]["sli_from"],
            "sli_to": list_data[i]["sli_to"],
            "sli": list_data[i]["sli"],
            "created_by": list_data[i]["created_by"],
            "last_updated_by": list_data[i]["last_updated_by"],
        }
        serializer = kpi_sli_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


# kpi_sli get
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_range_kpi_sli(request, start, end):
    pers_len = kpi_sli.objects.filter(delete_flag="N").count()
    pers = kpi_sli.objects.filter(delete_flag="N")[start:end]
    serializer = kpi_sli_serializer(pers, many=True)
    return Response({"data": serializer.data, "data_length": pers_len})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_sli(request, to=0):
    if to == 0:
        pers = kpi_sli.objects.filter(delete_flag="N")
    else:
        pers = kpi_sli.objects.filter(id=id)
    serializer = kpi_sli_serializer(pers, many=True)
    return Response(serializer.data)


# kpi_sli Update
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_kpi_sli(request, id):
    list_data = request.data
    for i in range(len(list_data)):
        item = kpi_sli.objects.get(id=list_data[i]["id"])
        serializer = kpi_sli_serializer(instance=item, data=list_data[i])

        if serializer.is_valid():
            serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)
    return Response(serializer.data, status=status.HTTP_200_OK)


# kpi_sli Delete
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_kpi_sli(request, id):
    CurView = kpi_sli.objects.get(id=id)
    data = request.data

    if CurView.delete_flag != data["delete_flag"]:
        CurView.delete_flag = data["delete_flag"]

    CurView.save()

    serializer = kpi_sli_serializer(CurView)
    return Response(serializer.data, status=status.HTTP_200_OK)


# todo csv uplode working code
# def using_pandas(file_path,table,id):
#     print("table_name",table)
#     uri = "mysql://root:@localhost:3306/score_card"
#     df = pd.read_csv(file_path)
#     df = df.rename(columns=lambda x: x.lower().replace(' ', '_'))
#     new_cols = pd.DataFrame({'created_by': [id]*len(df), 'last_updated_by': [id]*len(df), 'delete_flag': 'N'*len(df)})
#     df = pd.concat([df, new_cols], axis=1)
#     print("head",df.columns.values)
#     # df = df.rename(columns={'Currency code': 'currency_code','Currency name': 'currency_name','Sign': 'sign'})
#     # db_settings = settings.DATABASES['default']
#     # uri = f"{db_settings['ENGINE']}://{db_settings['USER']}:{db_settings['PASSWORD']}@{db_settings['HOST']}:{db_settings['PORT']}/{db_settings['NAME']}"
#     engine = create_engine(uri)
#     df.to_sql('tb_sc_'+table, con=engine, if_exists='append', index=False)

# @api_view(['POST'])
# def Csv_insert(request,id):
#     if 'file' in request.FILES:
#         file = request.FILES['file']
#         table= request.data.get('table')
#         # table_name='tb_sc_'+table
#         try:
#             using_pandas(file,table,id)
#         except Exception  as e:
#             error_message = str(e)
#             start_index = error_message.find('Duplicate entry')
#             end_index = error_message.find('\"', start_index)
#             duplicate_entry_message = error_message[start_index:end_index+1]

            # Print the extracted error message
            # print(error_message)
#             return Response({'error': duplicate_entry_message.replace('\"','') }, status=status.HTTP_404_NOT_FOUND)

#     return Response("Success",status=status.HTTP_200_OK)
# todo csv uplode working code end


# todo csv uplode for user and user_group working code
def using_pandas(file_path, table, id):
    # print("table_name",table)
    # uri = "mysql://root:@localhost:3306/score_card"
    df = pd.read_csv(file_path)
    df = df.rename(columns=lambda x: x.lower().replace(" ", "_"))

    if table == "user":
        new_cols = pd.DataFrame(
            {
                "date_joined": [date.today()],
                "is_active": [1],
                "is_staff": [1],
                "is_superuser": [0],
            }
        )
        df = pd.concat([df, new_cols], axis=1)

    # ? code for geting uri dynamically
    db_settings = def_set.DATABASES["default"]
    uri = f"{db_settings['ENGINE'].split('.')[-1]}://{db_settings['USER']}:{db_settings['PASSWORD']}@{db_settings['HOST']}:{db_settings['PORT']}/{db_settings['NAME']}"
    # ? code for geting uri dynamically end

    engine = create_engine(uri)
    # try:
    # if table=="user_groups":
        # print("if")
    #     df_list_group=[]
    #     df_list_user=[]
    #     for i in df.user_group:
    #         group_data=ConvertQuerysetToJson(Group.objects.filter(name=i))
    #         df_list_group.append(group_data["id"])
    #     for i in df.username:
    #         user_data=ConvertQuerysetToJson(User.objects.filter(username=i))
    #         df_list_user.append(user_data["id"])
    #     df_data={'group_id':df_list_group,'user_id':df_list_user}
    #     new_df=pd.DataFrame(df_data)
    #     new_df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)
        # print("new_df",new_df)
    # elif table=="user":
        # print("elif")
    #     new_df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)
    # else:
        # print("elif")
    #     new_df.to_sql('tb_sc_'+table, con=engine, if_exists='append', index=False)

    # except Exception as e:
    # print(f'Error inserting data: {str(e)}')
    # exit the program or continue with other operations

    if table == "user_groups":
        # print("if")
        df_list_group = []
        df_list_user = []
        for i in df.user_group:
            group_data = ConvertQuerysetToJson(Group.objects.filter(name=i))
            df_list_group.append(group_data["id"])
        for i in df.username:
            user_data = ConvertQuerysetToJson(User.objects.filter(username=i))
            df_list_user.append(user_data["id"])
        df_data = {"group_id": df_list_group, "user_id": df_list_user}
        new_df = pd.DataFrame(df_data)
        new_df.to_sql("auth_" + table, con=engine, if_exists="append", index=False)
        # print("new_df", new_df)
    elif table == "user":
        # print("elif")
        df.to_sql("auth_" + table, con=engine, if_exists="append", index=False)
    else:
        # print("else")
        df.to_sql("tb_sc_" + table, con=engine, if_exists="append", index=False)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def Csv_insert(request, id):
    if "file" in request.FILES:
        file = request.FILES["file"]
        table = request.data.get("table")
        try:
            using_pandas(file, table, id)
        except Exception as e:
            error_message = str(e)
            start_index = error_message.find("Duplicate entry")
            end_index = error_message.find('"', start_index)
            duplicate_entry_message = error_message[start_index : end_index + 1]

            # Print the extracted error message
            # print("Error", error_message)
            return Response(
                {"error": duplicate_entry_message.replace('"', "")},
                status=status.HTTP_404_NOT_FOUND,
            )
        else:
            return Response("Success", status=status.HTTP_200_OK)


# todo user and user_group code ends

# ! test of csv uplode to user and user_group
# def using_pandas(file_path,table,id):
#     # uri = "mysql://root:@localhost:3306/score_card"
#     df = pd.read_csv(file_path)
#     df = df.rename(columns=lambda x: x.lower().replace(' ', '_'))

#     if table=="user":
#         new_cols = pd.DataFrame({'date_joined': [date.today()]*len(df),'is_active':[1]*len(df), 'is_staff': [1]*len(df),'is_superuser': [0]*len(df),'password':['pbkdf2_sha256$320000$9lF2JLqlO1HnrtzetIfQo9$WyuVdT2Ykb8eJ83pNMpCDZTwM4xYfhlQzrNcOieHY1Y=']*len(df)})
#         df = pd.concat([df, new_cols], axis=1)

#     # ? code for geting uri dynamically
#     db_settings = def_set.DATABASES['default']
#     uri = f"{db_settings['ENGINE'].split('.')[-1]}://{db_settings['USER']}:{db_settings['PASSWORD']}@{db_settings['HOST']}:{db_settings['PORT']}/{db_settings['NAME']}"
#     # ? code for geting uri dynamically end
#     engine = create_engine(uri)

#     # result = engine.execute('SELECT 1')
    # print(result.fetchone())
#     try:
#         # if table=="user_groups":
        #     print("if")
#         #     df_list_group=[]
#         #     df_list_user=[]
#         #     for i in df.user_group:
#         #         group_data=ConvertQuerysetToJson(Group.objects.filter(name=i))
#         #         df_list_group.append(group_data["id"])
#         #     for i in df.username:
#         #         user_data=ConvertQuerysetToJson(User.objects.filter(username=i))
#         #         df_list_user.append(user_data["id"])
#         #     df_data={'group_id':df_list_group,'user_id':df_list_user}
#         #     new_df=pd.DataFrame(df_data)
#         #     new_df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)
        #     print("new_df",new_df)
#         # elif table=="user":
        #     print("elif")
#         #     new_df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)
#         # else:
        #     print("elif")
#         #     new_df.to_sql('tb_sc_'+table, con=engine, if_exists='append', index=False)
        # print(f'dataframe:{df}')

#         df2=df[["user_group"]].copy()
#         df.drop('user_group', inplace=True, axis=1)

#         # df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)

#     except Exception as e:
        # print(f'Error inserting data: {str(e)}')
#         # exit the program or continue with other operations

#     else:
#         table_name = "auth_user"
#         data_df = pd.read_sql_table(table_name, con=engine)
#         # merged=data_df.merge(df, on=['username'], how='left',indicator=True)
        # print(f"df1 is username:{df}")
        # print(f"df2 is username:{data_df.columns}")

#         merged=data_df[~(data_df.username.isin(df.username))]
        # print(f'{merged}')
        # print(f'data_df;{data_df}')
#         # with engine as connection:
#         #     # result = connection.execute(text("select * from auth_user"))
#         #     data_df=pd.read_table('auth_user',connection)
        #     print(f"data_df:{data_df}")
#             # for row in result:
            #     print("username:", row)

#             # result = connection.execute('select * from auth_user')
            # print(result.fetchall())

#             # for row in result:
            #     print("username:", row)

#         # user_data=pd.read_sql('SELECT * FROM auth_user',con=engine)
        # print(f"user{user_data}")
#         # df_list_group=[]
#         # df_list_user=[]
#         # for i in df2.user_group:
#         #     group_data=ConvertQuerysetToJson(Group.objects.filter(name=i))
#         #     df_list_group.append(group_data["id"])
#         # # for i in df.username:
#         # #     user_data=ConvertQuerysetToJson(User.objects.filter(username=i))
#         # #     df_list_user.append(user_data["id"])
#         # df_data={'group_id':df_list_group,'user_id':df_list_user}
#         # new_df=pd.DataFrame(df_data)
        # print("new_df",new_df)
#         # df.to_sql('auth_user_groups', con=engine, if_exists='append', index=False)

#     # if table=="user_groups":
    #     print("if")
#     #     df_list_group=[]
#     #     df_list_user=[]
#     #     for i in df.user_group:
#     #         group_data=ConvertQuerysetToJson(Group.objects.filter(name=i))
#     #         df_list_group.append(group_data["id"])
#     #     for i in df.username:
#     #         user_data=ConvertQuerysetToJson(User.objects.filter(username=i))
#     #         df_list_user.append(user_data["id"])
#     #     df_data={'group_id':df_list_group,'user_id':df_list_user}
#     #     new_df=pd.DataFrame(df_data)
#     #     new_df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)
    #     print("new_df",new_df)
#     # elif table=="user":
    #     print("elif")
#     #     new_df.to_sql('auth_'+table, con=engine, if_exists='append', index=False)
#     # else:
    #     print("else")
#     #     new_df.to_sql('tb_sc_'+table, con=engine, if_exists='append', index=False)

# @api_view(['POST'])
# def Csv_insert(request,id):
#     if 'file' in request.FILES:
#         file = request.FILES['file']
#         table= request.data.get('table')
#         try:
#             using_pandas(file,table,id)
#         except Exception  as e:
#             error_message = str(e)
#             start_index = error_message.find('Duplicate entry')
#             end_index = error_message.find('\"', start_index)
#             duplicate_entry_message = error_message[start_index:end_index+1]
            # Print the extracted error message
            # print("Error",error_message)
#             # return Response({'error': duplicate_entry_message.replace('\"','') }, status=status.HTTP_404_NOT_FOUND)

#             return Response({'error':  error_message}, status=status.HTTP_404_NOT_FOUND)
#         else:
#             return Response("Success",status=status.HTTP_200_OK)

# ! test of csv uplode to user and user_group code ends


class search_scorecard_description(generics.ListAPIView):
    queryset = scorecard.objects.filter(delete_flag="N")
    serializer_class = scorecard_serializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["$scorecard_description"]


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def filter_scorecard_description(request, id):
    org = scorecard.objects.filter(id=id, delete_flag="N")
    serializer = scorecard_serializer(org, many=True)
    return Response(serializer.data)


# KPI score Intitive

# Get


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_sc_initiative(request):
    view = initiative.objects.all()
    serializer = initiative_serializer(view, many=True)
    return Response(serializer.data)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_sc_initiative_details(request):
    view = initiative.objects.all().values()
    scorecard_data = scorecard.objects.all().values('id','scorecard_description')
    kpi_data = kpi_details.objects.all().values('id','kpi_code','kpi')
    # serializer = initiative_serializer(view, many=True)
    for iv in view:
        iv['target_date'] = iv['target_date'].strftime("%Y-%m-%d")
        if iv['status'] == 'in_progress':
            iv['status'] = 'In Progress'
        elif iv['status'] == 'not_started':
            iv['status'] = 'Not Started'
        elif iv['status'] == 'complete':
            iv['status'] = 'Completed'
        if len(kpi_data.filter(id=iv['kpi_id_id'])) == 1:
            iv['kpi_name'] = kpi_data.filter(id=iv['kpi_id_id'])[0]['kpi_code']
            iv['kpi_data'] = kpi_data
            iv['scorecard_data'] = scorecard_data
    return Response(view)
    # return Response(serializer.data)


# Add


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_sc_initiative(request):
    listData = request.data
    print(listData)
    for i in range(len(listData)):
        if 'id' in listData[i]:
            item = initiative.objects.get(id=listData[i]['id'])
            print("item", item)
            serializer = initiative_serializer(instance=item, data=listData[i])
            # if serializer.is_valid():
            #     serializer.save()
            #     return Response(serializer.data, status=status.HTTP_201_CREATED)
            # else:
            #     print("error", serializer.errors)
        else:
            data = {
                "scorecard_description": listData[i]["scorecard_description"],
                "action_item": listData[i]["action_item"],
                "target_date": listData[i]["target_date"],
                "ownership": listData[i]["ownership"],
                "status": listData[i]["status"],
                "comments": listData[i]["comments"] if 'comments' in listData[i] else '' ,
                "kpi_id": listData[i]["kpi_id"],
                "objective_id": listData[i]["objective_id"],
                "perspective_id": listData[i]["perspective_id"],
                "scorecard_id": listData[i]["scorecard_id"],
                "created_by": listData[i]["created_by"],
                "last_updated_by": listData[i]["last_updated_by"],
            }
            serializer = initiative_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# SMTP


@api_view(["GET"])
def get_smtp(request):
    data = smtp_configure_serializer(
        smtp_configure.objects.filter(delete_flag="N"), many=True
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
            # print("mail_res", mail_res)
            if mail_res == "true":
                # print("Mail Send")
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                # return Response("Mail Send",status=status.HTTP_200_OK)
            else:
                # print("Failed to send, Please check your details")
                return Response(
                    "Failed to connect smtp server. Please check your details",
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # if serializer.is_valid():
            #     serializer.save()
            #     return Response(serializer.data, status=status.HTTP_200_OK)
            # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
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
            # print("mail_res", mail_res)
            if mail_res == "true":
                # print("Mail Send")
                serializer = smtp_configure_serializer(data=data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                # return Response("Mail Send",status=status.HTTP_200_OK)
            else:
                # print("Failed to send, Please check your details")
                return Response(
                    "Failed to connect smtp server. Please check your details",
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# forgot_password


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

        # finalPassword = "".join(randomPassword + random.choice(special_characters))

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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_actuals_monthly_score(request):
    view = kpi_actuals_monthly_score.objects.all()
    # view = kpi_actuals_monthly_score.objects.filter(scorecard_id=20)
    serializer = kpi_actuals_monthly_score_serializer(view, many=True)
    return Response(serializer.data)


# @api_view(['GET'])
# def get_kpi_actuals_monthly_score(request):
#     # listData = request.data
#     view = kpi_actuals_monthly_score_2.objects.all()
#     serializer = kpi_actuals_monthly_score_2_serializer(view, many=True)
#     return Response(serializer.data)

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


# ! test


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def ins_scorecard_details_objective_kpi(request, id):
    updateData = request.data
    error = []
    scdetails_data = []
    scobjective_data = []
    sckpi_data = []
    for i in range(len(updateData)):
        if "d_flag" not in updateData[i]:
            data = {
                "scorecard_id": updateData[i]["scorecard_id"],
                "weight": updateData[i]["weight"],
                "perspective_id": updateData[i]["perspective_id"],
                "created_by": updateData[i]["created_by"],
                "last_updated_by": updateData[i]["last_updated_by"],
            }

            sc_serializer = scorecard_details_serializer(data=data)
            if sc_serializer.is_valid():
                sc_serializer.save()
                scdetails_data.append(sc_serializer.data)
                details_id = sc_serializer.data["id"]
                # details_id = 1

                if len(updateData[i]["goals"]) != 0:
                    for j in range(len(updateData[i]["goals"])):
                        if "d_flag" not in updateData[i]["goals"][j]:
                            businessdata = {
                                "scorecard_id": updateData[i]["goals"][j][
                                    "scorecard_id"
                                ],
                                "scorecard_details_id": details_id,
                                "weight": updateData[i]["goals"][j]["weight"],
                                "objective_code": updateData[i]["goals"][j][
                                    "objective_code"
                                ],
                                "objective_description": updateData[i]["goals"][j][
                                    "objective_description"
                                ],
                                "created_by": updateData[i]["goals"][j]["created_by"],
                                "last_updated_by": updateData[i]["goals"][j][
                                    "last_updated_by"
                                ],
                            }

                            Sc_ins_serializer = business_goals_objectives_serializer(
                                data=businessdata
                            )
                            if Sc_ins_serializer.is_valid():
                                Sc_ins_serializer.save()
                                scobjective_data.append(Sc_ins_serializer.data)
                                objective_id = Sc_ins_serializer.data["id"]
                                # objective_id = 1

                                for k in range(len(updateData[i]["goals"][j]["kpi"])):
                                    kpi_data = {
                                        "perspective_id": updateData[i]["goals"][j][
                                            "kpi"
                                        ][k]["perspective_id"],
                                        "objective_id": objective_id,
                                        "scorecard_id": updateData[i]["goals"][j][
                                            "kpi"
                                        ][k]["scorecard_id"],
                                        "scorecard_details_id": details_id,
                                        "kpi_code": updateData[i]["goals"][j]["kpi"][k][
                                            "kpi_code"
                                        ],
                                        "kpi": updateData[i]["goals"][j]["kpi"][k][
                                            "kpi"
                                        ],
                                        "ytd": updateData[i]["goals"][j]["kpi"][k][
                                            "ytd"
                                        ],
                                        "frequency": updateData[i]["goals"][j]["kpi"][
                                            k
                                        ]["frequency"],
                                        "weight": updateData[i]["goals"][j]["kpi"][k][
                                            "weight"
                                        ],
                                        "measure": updateData[i]["goals"][j]["kpi"][k][
                                            "measure"
                                        ],
                                        "baseline": updateData[i]["goals"][j]["kpi"][k][
                                            "baseline"
                                        ],
                                        "target": updateData[i]["goals"][j]["kpi"][k][
                                            "target"
                                        ],
                                        "min": updateData[i]["goals"][j]["kpi"][k][
                                            "min"
                                        ],
                                        "max": updateData[i]["goals"][j]["kpi"][k][
                                            "max"
                                        ],
                                        "optimization": updateData[i]["goals"][j][
                                            "kpi"
                                        ][k]["optimization"],
                                        "chart_type": updateData[i]["goals"][j]["kpi"][
                                            k
                                        ]["chart_type"],
                                        "period_type": updateData[i]["goals"][j]["kpi"][
                                            k
                                        ]["period_type"],
                                        "created_by": updateData[i]["goals"][j]["kpi"][
                                            k
                                        ]["created_by"],
                                        "last_updated_by": updateData[i]["goals"][j][
                                            "kpi"
                                        ][k]["last_updated_by"],
                                    }

                                    sc_kpi_serializer = kpi_details_serializer(
                                        data=kpi_data
                                    )
                                    if sc_kpi_serializer.is_valid():
                                        sc_kpi_serializer.save()
                                        sckpi_data.append(sc_kpi_serializer.data)
                                    else:
                                        error.append(Sc_ins_serializer.errors)
                            else:
                                error.append(Sc_ins_serializer.errors)
            else:
                error.append(sc_serializer.errors)
        else:
            del_data = scorecard_details.objects.filter(id=updateData[i]["id"]).update(
                delete_flag="Y"
            )
            get_bg_data = list(
                business_goals_objectives.objects.filter(
                    scorecard_id=updateData[i]["scorecard_id"],
                    scorecard_details_id=updateData[i]["id"],
                )
            )
            for k in get_bg_data:
                del_data = business_goals_objectives.objects.filter(id=k.id).update(
                    delete_flag="Y"
                )
    if not error:
        return Response(
            {"scdet": scdetails_data, "scobj": scobjective_data, "sckpi": sckpi_data},
            status=status.HTTP_200_OK,
        )
    else:
        return Response(error, status=status.HTTP_400_BAD_REQUEST)


#! test ends


# kpi_pin_dashboard data post


@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def ins_kpi_pin_dashboard(request):
    kpi_pin_data = request.data
    pinData = {
        "kpi_name": kpi_pin_data["kpi_name"],
        "kpi_id": kpi_pin_data["kpi_id"],
        "user_id": kpi_pin_data["user_id"],
        "kpi_score": kpi_pin_data["kpi_score"],
        "created_by": kpi_pin_data["created_by"],
        "last_updated_by": kpi_pin_data["last_updated_by"],
    }
    kpi_pin_serializer = kpi_pin_dashboard_serializer(data=pinData)

    if kpi_pin_serializer.is_valid():
        kpi_pin_serializer.save()
        return Response(kpi_pin_serializer.data, status=status.HTTP_201_CREATED)
    else:
        return Response(kpi_pin_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# get all kpi pin
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_kpi_pin_dashboard(request, id=0):
    if id == 0:
        pinData = kpi_pin_dashboard.objects.filter(pin_flag="Y")
    else:
        pinData = kpi_pin_dashboard.objects.filter(user_id=id, pin_flag="Y")

    pin_serializer = kpi_pin_dashboard_serializer(pinData, many=True)
    return Response(pin_serializer.data)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_kpi_pin_dashboard(request):
    kpi_pin_data = request.data
    kpi_pin_serializer = kpi_pin_dashboard_serializer(data=kpi_pin_data)

    if kpi_pin_serializer.is_valid():
        kpi_id = kpi_pin_serializer.validated_data["kpi_id"]
        pinned_kpi_data = kpi_pin_dashboard.objects.filter(kpi_id=kpi_id)

        if pinned_kpi_data.exists():
            pinned_kpi_data.delete()
        else:
            kpi_pin_serializer.save()

        return Response(kpi_pin_serializer.data, status=status.HTTP_200_OK)

    return Response(kpi_pin_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# change pin_flag
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def del_kpi_pin_dashboard(request, id=0):
    pinView = kpi_pin_dashboard.objects.get(id=id)
    pinData = request.data
    if pinView.pin_flag != pinData["pin_flag"]:
        pinView.pin_flag = pinData["pin_flag"]
    if pinView.last_updated_by != pinData["last_updated_by"]:
        pinView.last_updated_by = pinData["last_updated_by"]
    pinView.save()

    pinSerializer = kpi_pin_dashboard_serializer(pinView)
    return Response(pinSerializer.data, status=status.HTTP_200_OK)


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_vw_kpi_pin_dashboard(request):
#     view = vw_kpi_pin_dashboard.objects.all()
#     serializer = vw_kpi_pin_dashboard_serializer(view, many=True)
#     return Response(serializer.data)


# ! test


def fun_upd_scorecard_details(data, scid):
    sc_det_data = {
        "scorecard_id": scid,
        "weight": data["weight"],
        "weight_editable": data["weight_editable"] if "weight_editable" in data else False,
        "perspective_id": data["perspective_id"],
        "created_by": data["created_by"],
        "last_updated_by": data["last_updated_by"],
    }
    if "id" in data:
        if "delete_flag" not in data:
            sc_det_item = scorecard_details.objects.get(id=data["id"])
            sc_det_serializer = scorecard_details_serializer(
                instance=sc_det_item, data=sc_det_data
            )

            if sc_det_serializer.is_valid():
                sc_det_serializer.save()
                if len(data["BusinessGoal"]) != 0:
                    for i in range(len(data["BusinessGoal"])):
                        fun_upd_objective(
                            data["BusinessGoal"][i], scid, sc_det_serializer.data["id"], data["perspective_id"]
                        )
        else:
            del_data = scorecard_details.objects.filter(id=data["id"]).update(delete_flag="Y")
            for i in range(len(data["BusinessGoal"])):
                fun_upd_objective(
                    data["BusinessGoal"][i], scid, data["id"], data["perspective_id"]
                )

    else:
        if "delete_flag" not in data:   
            print(data)
            sc_det_serializer = scorecard_details_serializer(data=sc_det_data)
            if sc_det_serializer.is_valid():
                sc_det_serializer.save()
                if len(data["BusinessGoal"]) != 0:
                    for i in range(len(data["BusinessGoal"])):
                        fun_upd_objective(
                            data["BusinessGoal"][i], scid, sc_det_serializer.data["id"], data["perspective_id"]
                        )
            else:
                print("error", sc_det_serializer.errors)


def fun_upd_objective(data, scid, scdid, perid):
    businessdata = {
        "scorecard_id": scid,
        "scorecard_details_id": scdid,
        "weight": data["weight"],
        "weight_editable": data["weight_editable"] if "weight_editable" in data else False,
        "objective_code": data["objective_code"],
        "objective_description": data["objective_description"],
        "created_by": data["created_by"],
        "last_updated_by": data["last_updated_by"],
    }
    if "id" in data:
        if "delete_flag" not in data:
            sc_obj_item = business_goals_objectives.objects.get(id=data["id"])

            Sc_obj_serializer = business_goals_objectives_serializer(
                instance=sc_obj_item, data=businessdata
            )
            if Sc_obj_serializer.is_valid():
                Sc_obj_serializer.save()

                if len(data["kpi_items"]) != 0:
                    for i in range(len(data["kpi_items"])):
                        fun_kpi_details(
                            data["kpi_items"][i],
                            scid,
                            scdid,
                            perid,
                            Sc_obj_serializer.data["id"],
                        )
        else:
            del_data = business_goals_objectives.objects.filter(id=data["id"]).update(delete_flag="Y")
            if len(data["kpi_items"]) != 0:
                for i in range(len(data["kpi_items"])):
                    fun_kpi_details(
                        data["kpi_items"][i],
                        scid,
                        scdid,
                        perid,
                        data["id"],
                    )
    else:
        if "delete_flag" not in data:
            Sc_obj_serializer = business_goals_objectives_serializer(data=businessdata)
            if Sc_obj_serializer.is_valid():
                Sc_obj_serializer.save()

                if len(data["kpi_items"]) != 0:
                    for i in range(len(data["kpi_items"])):
                        fun_kpi_details(
                            data["kpi_items"][i],
                            scid,
                            scdid,
                            perid,
                            Sc_obj_serializer.data["id"],
                        )


def fun_kpi_details(data, scid, scdid, perid, objid):
    kpi_data = {
        # "perspective_id": data["perspective_id"],
        "perspective_id": perid,
        "objective_id": objid,
        "scorecard_id": scid,
        "scorecard_details_id": scdid,
        "kpi_code": data["kpi_code"],
        "kpi": data["kpi"],
        "ytd": data["ytd"],
        "frequency": data["frequency"],
        "weight": data["weight"],
        "weight_editable": data["weight_editable"] if "weight_editable" in data else False,
        "measure": data["measure"],
        "baseline": data["baseline"] if data["baseline"] != '' else None,
        "target": data["target"],
        "min": data["min"],
        "max": data["max"],
        "optimization": data["optimization"],
        "chart_type": data["chart_type"],
        "period_type": data["period_type"],
        "actual_type": data["actual_type"],
        "created_by": data["created_by"],
        "last_updated_by": data["last_updated_by"],
    }
    if "id" in data:
        if "delete_flag" not in data:
            sc_kpi_item = kpi_details.objects.get(id=data["id"])
            sc_kpi_serializer = kpi_details_serializer(
                instance=sc_kpi_item, data=kpi_data
            )
            if sc_kpi_serializer.is_valid():
                sc_kpi_serializer.save()
                # print("sc", sc_kpi_serializer.data)
                # Kpi user insertion
                if len(data["Indicators"]) != 0:
                    for i in range(len(data["Indicators"])):
                        fun_kpi_sli(
                            data["Indicators"][i],
                            scid,
                            scdid,
                            objid,
                            sc_kpi_serializer.data["id"],
                        )

                if "kpiUser" in data:
                    fun_kpi_user_access(
                        data["kpiUser"],
                        sc_kpi_serializer.data["id"],
                        kpi_data["created_by"],
                        kpi_data["last_updated_by"],
                    )
                
                if "kpiOwner" in data and len(data["kpiOwner"]) != 0:
                    fun_kpi_owner_access(
                        data["kpiOwner"],
                        sc_kpi_serializer.data["id"],
                        kpi_data["created_by"],
                        kpi_data["last_updated_by"],
                    )

                if "LogicData" in data and data["actual_type"] == 'Auto':
                    print(12)
                    fun_compData(
                        data["LogicData"],
                        data["measure"],
                        sc_kpi_serializer.data["id"],
                        kpi_data["created_by"],
                        kpi_data["last_updated_by"],
                    )
        else:
            del_data = kpi_details.objects.filter(id=data["id"]).update(delete_flag="Y")
            if len(data["Indicators"]) != 0:
                for i in range(len(data["Indicators"])):
                    fun_kpi_sli(
                        data["Indicators"][i],
                        scid,
                        scdid,
                        objid,
                        data["id"],
                    )

    else:
        if "delete_flag" not in data:
            sc_kpi_serializer = kpi_details_serializer(data=kpi_data)
            if sc_kpi_serializer.is_valid():
                sc_kpi_serializer.save()
                # print("kpi_succ", data["Indicators"])
                if len(data["Indicators"]) != 0 and data["Indicators"] == False:
                    for i in range(len(data["Indicators"])):
                        fun_kpi_sli(
                            data["Indicators"][i],
                            scid,
                            scdid,
                            objid,
                            sc_kpi_serializer.data["id"],
                        )
                if "kpiUser" in data and len(data["kpiUser"]) != 0:
                    fun_kpi_user_access(
                        data["kpiUser"],
                        sc_kpi_serializer.data["id"],
                        kpi_data["created_by"],
                        kpi_data["last_updated_by"],
                    )
                if "kpiOwner" in data and len(data["kpiOwner"]) != 0:
                    fun_kpi_owner_access(
                        data["kpiOwner"],
                        sc_kpi_serializer.data["id"],
                        kpi_data["created_by"],
                        kpi_data["last_updated_by"],
                    )
                if "LogicData" in data and data["actual_type"] == 'Auto':
                    print(1)
                    fun_compData(
                        data["LogicData"],
                        data["measure"],
                        sc_kpi_serializer.data["id"],
                        kpi_data["created_by"],
                        kpi_data["last_updated_by"],
                    )
            else:
                print(sc_kpi_serializer.errors)

def fun_kpi_sli(data, scid, scdid, objid, kpiid):
    # print("kpi_sli", data)
    kpi_indicators_data = {
        "stop_light_indicator_from": data["stop_light_indicator_from"],
        "stop_light_indicator_to": data["stop_light_indicator_to"],
        "stop_light_indicator": data["stop_light_indicator"],
        "kpi_id": kpiid,
        "created_by": data["created_by"],
        "last_updated_by": data["last_updated_by"],
    }

    if "id" in data:
        if "delete_flag" not in data:
            sc_kpi_item = kpi_stop_light_indicators.objects.get(id=data["id"])
            sc_kpi_serializer = kpi_stop_light_indicators_serializer(
                instance=sc_kpi_item, data=kpi_indicators_data
            )
            if sc_kpi_serializer.is_valid():
                sc_kpi_serializer.save()
        else:
            del_data = kpi_stop_light_indicators.objects.filter(id=data["id"]).update(
                delete_flag="Y"
            )

    else:
        if "delete_flag" not in data:
            sc_kpi_serializer = kpi_stop_light_indicators_serializer(
                data=kpi_indicators_data
            )
            if sc_kpi_serializer.is_valid():
                sc_kpi_serializer.save()
                # print("sc_ind")


def fun_kpi_user_access(data, kpiid, cid, luid):
    return_data = []
    Del_serializer = kpi_user_access.objects.filter(kpi_id=kpiid)
    Del_serializer.delete()
    # print("data", data)
    for i in data:
        data = {
            "user_id": i,
            "kpi_id": kpiid,
            "created_by": cid,
            "last_updated_by": luid,
        }
        # print("data", data)
        serializer = kpi_user_Access_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return_data.append(serializer.data)
        else:
            # print(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(return_data, status=status.HTTP_201_CREATED)


def fun_kpi_owner_access(data, kpiid, cid, luid):
    return_data = []
    Del_serializer = kpi_user_access.objects.filter(kpi_id=kpiid, kpi_owner="Y")
    Del_serializer.delete()
    # print("data", data)
    for i in data:
        data = {
            "user_id": i,
            "kpi_id": kpiid,
            "kpi_owner": "Y",
            "created_by": cid,
            "last_updated_by": luid,
        }
        # print("data", data)
        serializer = kpi_user_Access_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return_data.append(serializer.data)
        else:
            # print(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(return_data, status=status.HTTP_201_CREATED)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def api_scorecard_scorecard_details_objective_kpi(request):
    updateData = request.data
    error = []
    if "id" in updateData:
        sc_item = scorecard.objects.get(id=updateData["id"])
        sc_serializer = scorecard_serializer(instance=sc_item, data=updateData)
        if sc_serializer.is_valid():
            sc_serializer.save()
            for i in range(len(updateData["ScoreCard_Details"])):
                fun_upd_scorecard_details(
                    updateData["ScoreCard_Details"][i], sc_serializer.data["id"]
                )
    else:
        sc_serializer = scorecard_serializer(data=updateData)
        if sc_serializer.is_valid():
            sc_serializer.save()
            for i in range(len(updateData["ScoreCard_Details"])):
                fun_upd_scorecard_details(
                    updateData["ScoreCard_Details"][i], sc_serializer.data["id"]
                )

    if not error:
        return Response("succ", status=status.HTTP_200_OK)
    else:
        return Response(error, status=status.HTTP_400_BAD_REQUEST)


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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_scorecard_report_generator(request, id=0):
    if id == 0:
        reports = kpi_actuals.objects.select_related("kpi_id")
    else:
        reports = user_access_definition.objects.select_related(
            "user_id", "menu_id"
        ).filter(user_id=id, menu_id=menu_id)
        print(reports.query)
    # data = kpi_actuals_serializer(
    #     reports, many=True, context={'request': request}).data
    data = kpi_details_with_actuals_serializer(
        reports, many=True, context={"request": request}
    ).data
    return Response(data, status=status.HTTP_200_OK)


@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_kpi_details_uom(request):
    cursor = connection.cursor()
    cursor.execute(
        "select kd.kpi,kd.frequency,p.perspective from tb_sc_kpi_details kd join tb_sc_perspectives p on kd.perspective_id = p.id"
    )
    result = cursor.fetchall()
    # print("result", result)
    json_rows = [
        dict(
            zip(
                (
                    "kpi",
                    "frequency",
                    "perspective",
                ),
                (str(key), *values),
            )
        )
        for key, *values in result
    ]
    # print(json.dumps(json_rows))
    return Response(json_rows, status=status.HTTP_200_OK)


@api_view(["GET"])
def get_kpi_details_uom_2(request):
    cursor = connection.cursor()
    # cursor.execute("select id, perspective from tb_sc_perspectives")
    cursor.execute(
        "select `kd`.`kpi` as kpi,`p`.`perspective` as perspective from `tb_sc_kpi_details` `kd` join `tb_sc_perspectives` `p` on `kd`.`perspective_id` = `p`.`id`"
    )
    result = cursor.fetchall()
    print(result)
    return Response(result, status=status.HTTP_200_OK)


# Get only admin details
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def checkadmin(request, username=""):
    # print(username)
    # employee = User.objects.filter(username=username,is_superuser=1, is_staff=1, is_active=1)
    # serializer = CheckAdminSerializer(employee, many=True)
    print("serializer.data", serializer.data)
    return Response(status=status.HTTP_200_OK)


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
        print("Error", serializer.errors)


@api_view(["GET"])
def get_license(request):
    current_datetime = datetime.datetime.now().date()
    licensed = user_license.objects.filter(delete_flag="N")
    serializer = user_license_serializer(licensed, many=True)
    return Response(
        {"data": serializer.data, "current_date": current_datetime},
        status=status.HTTP_200_OK,
    )


# pin chart to homepage
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_chat_pin_homepage(request):
    chart_pin_data = request.data

    chartPinData = {
        "kpi_id": chart_pin_data["kpi_id"],
        "chart_type": chart_pin_data["chart_type"],
        "user_id": chart_pin_data["user"],
        "created_by": chart_pin_data["created_by"],
        "last_updated_by": chart_pin_data["last_updated_by"],
    }

    chart_pin_serializer = pin_chart_to_homepage_serializer(data=chartPinData)

    if chart_pin_serializer.is_valid():
        chart_pin_serializer.save()
        return Response(chart_pin_serializer.data, status=status.HTTP_201_CREATED)
    else:
        return Response(chart_pin_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_chart_pin_dashboard(request):
    chart_pin_data = request.data
    chart_pin_serializer = pin_chart_to_homepage_serializer(data=chart_pin_data)

    if chart_pin_serializer.is_valid():
        kpi_id = chart_pin_serializer.validated_data["kpi_id"]
        pinned_data = pin_chart_to_homepage.objects.filter(kpi_id=kpi_id)

        if pinned_data.exists():
            pinned_data.delete()
        else:
            max_order_no = pin_chart_to_homepage.objects.aggregate(Max("order_no"))[
                "order_no__max"
            ]
            order_no = (max_order_no or 0) + 1
            chart_pin_serializer.validated_data["order_no"] = order_no
            chart_pin_serializer.save()

        return Response(chart_pin_serializer.data, status=status.HTTP_200_OK)

    return Response(chart_pin_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["PUT"])
def update_order_no(request):
    orderData = request.data
    for item in orderData:
        kpi_id = item["kpi_id"]
        order_no = item["order_no"]

        orderedCharts = pin_chart_to_homepage.objects.filter(kpi_id=kpi_id)

        if orderedCharts.exists():
            for orderchart in orderedCharts:
                orderchart.order_no = order_no
                orderchart.save()
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    return Response(status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_chart_pin_dashboard(request, id=0):
    if id == 0:
        pinData = pin_chart_to_homepage.objects.filter(pin_flag="Y")
    else:
        pinData = pin_chart_to_homepage.objects.filter(user_id=id, pin_flag="Y")

    pin_serializer = pin_chart_to_homepage_serializer(pinData, many=True)
    return Response(pin_serializer.data)


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
            # exist_session = session.objects.filter(uid=uid).update(lasttime=item['last_time'])
            serializer = session_serializer(instance=exist_session, data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(status=status.HTTP_201_CREATED)
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
                return Response(status=status.HTTP_200_OK)
    elif update == "close":
        cdata = {
            "lasttime": item["last_time"],
            "status": 0,
        }
        # exist_session = session.objects.filter(uid=uid, sid=item['access'])
        exist_session = session.objects.filter(uid=uid, sid=item["access"]).update(
            lasttime=item["last_time"], status=0
        )
        # serializer = session_serializer(instance=exist_session, data=cdata)
        if exist_session:
            # serializer.save()
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


@api_view(["PUT"])
def deletesession(request, uid=0):
    # exist_session = session.objects.filter(uid=uid).delete()
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
    sessionData = session_configuration.objects.filter(delete_flag='N')
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
        exist_session = session_configuration.objects.get(id=id, delete_flag="N")
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
        sso = sso_configure.objects.filter(delete_flag="N")
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


# Join notification and group table
from django.db.models import F, Q


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def notification_and_group(request, user_id):
    group_user_dict = {
        group.id: group.user_set.filter(id=user_id).values_list(
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
            # act_json.append(temp_json)
            get_notification = notification.objects.filter(
                permission=i, show_flag=1
            ).values()
    return Response(get_notification, status=status.HTTP_200_OK)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def notification_show_handle(request, id):
    notification_res = notification.objects.filter(id=id).update(show_flag=0)
    if notification_res:
        return Response(status=status.HTTP_200_OK)
    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def notification_kpi_show_handle(request, id):
    notification_res = kpi_pending_actions.objects.filter(id=id).update(delete_flag="Y")
    if notification_res:
        return Response(status=status.HTTP_200_OK)
    else:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    

# ***User Profile***


# View all
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user_profile(request, id=0):
    if id == 0:
        user = user_profile.objects.filter(delete_flag="N")
    else:
        user = user_profile.objects.filter(user_id=id)

    serializer = user_profile_serializer(user, many=True)
    
    return Response(serializer.data)


# Add
@api_view(["POST"])
@permission_classes([IsAuthenticated])
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
    # print(f"==>> profilePic: {profilePic}")
    # print(f"==>> =: {data['profile_pic']}")

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

def GetIndicatorArray(id):
    if(len(kpi_stop_light_indicators.objects.filter(kpi_id=id, delete_flag='N')) == 0):
        indicate = org_definition_stop_light_indicators.objects.filter(delete_flag='N').values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator")
    else:
        indicate = kpi_stop_light_indicators.objects.filter(kpi_id=id, delete_flag='N').values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator","kpi_id")
    
    return list(indicate)

def GetIndicator(id=0, score=0):
    # score = -2, 25, 50
    color_value = 'none'
    if id == 0:
        indicate = org_definition_stop_light_indicators.objects.filter(delete_flag='N').values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator")
    else:
        if(len(kpi_stop_light_indicators.objects.filter(kpi_id=id, delete_flag='N')) == 0):
            indicate = org_definition_stop_light_indicators.objects.filter(delete_flag='N').values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator")
        else:
            indicate = kpi_stop_light_indicators.objects.filter(kpi_id=id, delete_flag='N').values("id","stop_light_indicator_from","stop_light_indicator_to","stop_light_indicator","kpi_id")
    for d_indicate in indicate:
        if score == 0 and (d_indicate['stop_light_indicator_from'] == 0 or d_indicate['stop_light_indicator_from'] == 1):
            color_value = d_indicate['stop_light_indicator']
        elif d_indicate['stop_light_indicator_from'] <= score and d_indicate['stop_light_indicator_to'] >= score:
            color_value = d_indicate['stop_light_indicator']
        elif score > 100:
            color_value = d_indicate['stop_light_indicator']
    return color_value

def ScoreCalculation(data, all, actual_name='actuals', score_name='score', perf_name='performance', ind_name='indicator'):
    performance = ''
    if actual_name == 'prev_actuals' and len(data['actuals']) >= 2:
        data['actuals'].pop(len(data['actuals'])-1)
    d_actuals = data
    if all == 'true':
        actual_values = []
        for v_actuals in data['actuals']:
            d_actuals = v_actuals
            actual_values.append(v_actuals['actuals'])
        if data['ytd'] == 'Sum':
            d_actuals['actuals'] = sum(actual_values)
        elif data['ytd'] == 'Avg':
            d_actuals['actuals'] = sum(actual_values)/len(actual_values)
        elif data['ytd'] == 'Min':
            d_actuals['actuals'] = min(actual_values)
        elif data['ytd'] == 'Max':
            d_actuals['actuals'] = max(actual_values)
        data[actual_name] = d_actuals['actuals']
    else:
        d_actuals = data['actuals'][len(data['actuals'])-1]
    if d_actuals and len(d_actuals) > 0:
        if data['optimization'] in ('Minimum', 'minimum'):
            performance = (data['max'] - d_actuals['actuals']) / (data['max'] - data['target'])
            data[perf_name] = performance
            if int(round(performance*100, 0)) < 0:
                data[score_name] = 0
            elif int(round(performance*100, 0)) > 100:
                data[score_name] = 100
            else:
                data[score_name] = int(round(performance*100, 0))
            data[ind_name] = GetIndicator(data['id'], data[score_name])
            data['indicator_colors'] = GetIndicatorArray(data['id'])
        elif data['optimization'] in ('Maximum', 'maximum'):
            performance = (d_actuals['actuals'] - data['min']) / (data['target'] - data['min'])
            data[perf_name] = performance
            if int(round(performance*100, 0)) < 0:
                data[score_name] = 0
            elif int(round(performance*100, 0)) > 100:
                data[score_name] = 100
            else:
                data[score_name] = int(round(performance*100, 0))
            # data['score'] = 100 if int(round(int(data['weight'])/ 100 * round(performance * 100, 0),0)) > 100 else int(round(int(data['weight'])/ 100 * round(performance * 100, 0),0))
            data[ind_name] = GetIndicator(data['id'], data[score_name])
            data['indicator_colors'] = GetIndicatorArray(data['id'])

def GetObjectiveScoreCalculation(data):
    score = 0
    for d_kpi in data:
        # score = score + (d_kpi['score']*d_kpi['weight'])/100
        # print(d_kpi['score'], type(d_kpi['score']))
        # print(d_kpi['weight'], type(d_kpi['weight']))
        # print("d_kpi", d_kpi)
        # print("float(score)", float(score))
        score = float(score) + (float(d_kpi['score'])*float(d_kpi['weight']))/100
        # score = score + int(d_kpi['score'])
    return int(round(score, 0))
    # return int(round((int(score) * int(weight) / 100), 0))

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_scorecard_details_yet_kpi(request, id=0):
    if id != 0:
        sc = scorecard.objects.filter(id=id, delete_flag='N').values("id","scorecard_description","from_date","to_date","publish_flag")
        for d_sc in sc:
            scd = scorecard_details.objects.select_related("perspective_id").filter(scorecard_id=d_sc['id'], delete_flag='N').values("id","perspective_id","weight")
            d_sc['scorecard_details'] = list(scd)
            for d_scd in d_sc['scorecard_details']:
                pers = perspectives.objects.filter(id=d_scd['perspective_id'], delete_flag='N').values("id","perspective","description")
                d_scd['perspective'] = pers[0]['perspective']
                d_scd['description'] = pers[0]['description']
                obj = business_goals_objectives.objects.filter(scorecard_id=d_sc['id'], scorecard_details_id=d_scd['id'], delete_flag='N').values("id","objective_code","objective_description","weight").order_by('id')
                d_scd['objective'] = list(obj)
                for d_obj in d_scd['objective']:
                    kpi = kpi_details.objects.filter(scorecard_id=d_sc['id'], scorecard_details_id=d_scd['id'], objective_id=d_obj['id'], delete_flag='N').values("id","kpi_code","kpi","weight","target","min","max","optimization")
                    d_obj['kpi'] = list(kpi)
                    for d_kpi in d_obj['kpi']:
                        actuals = kpi_actuals.objects.filter(kpi_id=d_kpi['id'], delete_flag='N').values("id","period","actuals","actuals_date","actuals_boolean","summery")
                        initiate = initiative.objects.filter(kpi_id=d_kpi['id'], delete_flag='N').values("id","scorecard_description","action_item","target_date","ownership","target_date","status","comments")
                        d_kpi['actuals'] = list(actuals)
                        d_kpi['initiative'] = list(initiate)
                        d_kpi['scorecard_id'] = d_sc['id']
                        d_kpi['perspective_id'] = d_scd['id']
                        d_kpi['objective_id'] = d_obj['id']
                        # d_kpi['scorecard_id'] = d_sc['id']
                        if len(d_kpi['actuals']) != 0:
                            ScoreCalculation(d_kpi, all='false')
                        else:
                            d_kpi['score'] = 0
                        del d_kpi['actuals']
                    d_obj['score'] = GetObjectiveScoreCalculation(d_obj['kpi'])
                    if len(kpi) > 0:
                        d_obj['indicator'] = GetIndicator(score=d_obj['score'])
                    else:
                        d_obj['indicator'] = 'none'
                d_scd['score'] = GetObjectiveScoreCalculation(d_scd['objective'])
                d_scd['indicator'] = GetIndicator(score=d_scd['score'])
            d_sc['score'] = GetObjectiveScoreCalculation(d_sc['scorecard_details'])
            d_sc['indicator'] = GetIndicator(score=d_sc['score'])
        return Response(sc, status=status.HTTP_200_OK)



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_dashboard_view(request, id=0):
    if id != 0:
        kpi = kpi_details.objects.filter(id=id, delete_flag='N').values("id","kpi_code","kpi","weight","target","min","max","optimization","ytd")
        if len(kpi) == 1:
            actuals = kpi_actuals.objects.filter(kpi_id=kpi[0]['id'], delete_flag='N').values("id","period","actuals","actuals_date","actuals_boolean","summery")
            if len(actuals) > 0:
                kpi[0]['actuals'] = list(actuals)
                ScoreCalculation(kpi[0], all='false')
        else:
            org_data = []
            org_dict ={ 'score': 100,
                       'indicator': GetIndicator(0, 100),
                       'indicator_colors': GetIndicatorArray(0)
            }
            org_data.append(org_dict)
            return Response(org_data,status=status.HTTP_200_OK)
    return Response(kpi, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_curr_prev_actual_score(request, id=0):
    if id == 0:
        kpipin = kpi_pin_dashboard.objects.filter(pin_flag='Y').values("kpi_name","kpi_score","pin_flag","kpi_id","user_id","created_by","last_updated_by")
    else:
        kpipin = kpi_pin_dashboard.objects.filter(kpi_id=id,pin_flag='Y').values("kpi_name","kpi_score","pin_flag","kpi_id","user_id","created_by","last_updated_by")
        # kpi = kpi_details.objects.filter(id=id, delete_flag='N').values("id","kpi_code","kpi","weight","target","min","max","optimization","ytd","perspective_id","objective_id","scorecard_id")
    for d_kpipin in kpipin:
        kpi = kpi_details.objects.filter(id=d_kpipin['kpi_id'],delete_flag='N').values("id","kpi_code","kpi","weight","chart_type","target","min","max","optimization","ytd","perspective_id","objective_id","scorecard_id")
        for d_kpi in kpi:
            # kpipin = kpi_pin_dashboard.objects.filter(kpi_id=d_kpi['id'], pin_flag='Y').values("kpi_name","kpi_score","pin_flag","kpi_id","user_id","created_by","last_updated_by")
            actuals = kpi_actuals.objects.filter(kpi_id=d_kpi['id'], delete_flag='N').values("id","period","actuals","actuals_date","actuals_boolean","summery")
            d_kpi['actuals'] = list(actuals)
            if len(actuals) > 0:
                ScoreCalculation(d_kpi, all='true', actual_name='curr_actuals', score_name='curr_score', perf_name='curr_performance', ind_name='curr_actual_indicator')
                ScoreCalculation(d_kpi, all='true', actual_name='prev_actuals', score_name='prev_score', perf_name='prev_performance', ind_name='prev_actual_indicator')
            # d_kpi['kpipin'] = list(kpipin)
            if len(kpi) > 0:
                d_kpipin['id'] = kpi[0]['id']
                d_kpipin['kpi_code'] = kpi[0]['kpi_code']
                d_kpipin['kpi'] = kpi[0]['kpi']
                d_kpipin['weight'] = kpi[0]['weight']
                d_kpipin['target'] = kpi[0]['target']
                d_kpipin['chart_type'] = kpi[0]['chart_type']
                d_kpipin['min'] = kpi[0]['min']
                d_kpipin['max'] = kpi[0]['max']
                d_kpipin['optimization'] = kpi[0]['optimization']
                d_kpipin['curr_actuals'] = kpi[0]['curr_actuals']
                d_kpipin['curr_performance'] = kpi[0]['curr_performance']
                d_kpipin['curr_score'] = kpi[0]['curr_score']
                d_kpipin['curr_actual_indicator'] = kpi[0]['curr_actual_indicator']
                d_kpipin['prev_actuals'] = kpi[0]['prev_actuals']
                d_kpipin['prev_performance'] = kpi[0]['prev_performance']
                d_kpipin['prev_score'] = kpi[0]['prev_score']
                d_kpipin['prev_actual_indicator'] = kpi[0]['prev_actual_indicator']
                d_kpipin['scorecard_id'] = kpi[0]['scorecard_id']
                d_kpipin['perspective_id'] = kpi[0]['perspective_id']
                d_kpipin['objective_id'] = kpi[0]['objective_id']
            del d_kpi['actuals']
    # print(kpipin)
    return Response(kpipin, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_kpi_with_actuals(request):
    kpi_actual=[]
    kpi = kpi_details.objects.filter(delete_flag='N').values("id","kpi_code","kpi","target","chart_type","baseline","min","max")
    for d_kpi in kpi:
        
        actuals = kpi_actuals.objects.filter(kpi_id=d_kpi['id'] ,delete_flag='N').values("id","period","actuals")
        for d_actual in actuals:
            actual_data={}
            actual_data['id'] = d_kpi['id']
            actual_data['kpi'] = d_kpi['kpi']
            actual_data['baseline'] = d_kpi['baseline']
            actual_data['target'] = d_kpi['target']
            actual_data['min'] = d_kpi['min']
            actual_data['max'] = d_kpi['max']
            actual_data['chart_type'] = d_kpi['chart_type']
            actual_data['period'] = d_actual['period']
            actual_data['actuals'] = d_actual['actuals']
            kpi_actual.append(actual_data)
    return Response(kpi_actual, status=status.HTTP_200_OK)


@api_view(["GET"])
def get_kpi_details_uom_3(request):
    result = navigation_menu_details.objects.all().values()
    final_list = []
    for d in result:
        d['created_date'] = '0000-00-00 00:00:00.000000'
        d['last_updated_date'] = '0000-00-00 00:00:00.000000'
        demo1={}
        demo1['model'] = 'base.navigation_menu_details'
        # demo1['pk'] = d['id']
        # del d['id']
        demo1['fields'] = dict(d)
        final_list.append(demo1)
    
    # serializer = chart_attributes_serializer(result, many=True)
    return Response(final_list, status=status.HTTP_200_OK)



# *** Query Builder DB Connect***


# View all
@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_rb_db_connect_table(request, id=0):
    if id == 0:
        rb = rb_db_connect_table.objects.filter(delete_flag="N")
    else:
        rb = rb_db_connect_table.objects.filter(id=id)

    serializer = rb_db_connect_table_serializer(rb, many=True)
    return Response(serializer.data)

# GET

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_range_rb_db_connect_table(request, start, end):
    pers_len = rb_db_connect_table.objects.filter(delete_flag="N").count()
    pers = rb_db_connect_table.objects.filter(delete_flag="N")[start:end]
    pers_csv_export = rb_db_connect_table.objects.filter(delete_flag="N")
    serializer = rb_db_connect_table_serializer(pers, many=True)
    serializer_csv_export = rb_db_connect_table_serializer(pers_csv_export, many=True)
    return Response(
        {
            "data": serializer.data,
            "data_length": pers_len,
            "csv_data": serializer_csv_export.data,
        }
    )


# ADD
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ins_rb_db_connect_table(request):
    data = {
        "connection_name":request.data.get("connection_name"),
        "database_name":request.data.get("database_name"),
        "database_type": request.data.get("database_type"),
        "user_name": request.data.get("user_name"),
        "password": request.data.get("password"),
        "host_id": request.data.get("host_id"),
        "port": request.data.get("port"),
        "service_name_or_SID": request.data.get("service_name_or_SID"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = rb_db_connect_table_serializer(data=data)
    
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
        # print("error_data", error_data, len(error_data))
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
                "connection_name": 0,
                "database_name": 1,
                "database_type": 2,
                "user_name": 3,
                "password": 4,
                "host_id": 5,
                "port": 6, 
                "service_name_or_SID": 7,
            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data
        # print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)
    

# ADD
@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def rb_test_db_connection(request):
    data = {
        "connection_name":request.data.get("connection_name"),
        "database_name":request.data.get("database_name"),
        "database_type": request.data.get("database_type"),
        "user_name": request.data.get("user_name"),
        "password": request.data.get("password"),
        "host_id": request.data.get("host_id"),
        "port": request.data.get("port"),
        "service_name_or_SID": request.data.get("service_name_or_SID"),
        "created_by": request.data.get("created_by"),
        "last_updated_by": request.data.get("last_updated_by"),
    }

    serializer = rb_db_connect_table_serializer(data=data)
    
    all_serializer_fields = list(serializer.fields.keys())

    # print("all_serializer_fields",all_serializer_fields)

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    # print("required_serializer_fields",required_serializer_fields)

    if serializer.is_valid():
        print("serializer data",type(serializer.data),serializer.data['database_type'])
        smpl = serializer.data
        try:
            db_type = serializer.data['database_type']
            if db_type=='SQL':
                mydb = sqlConnect.connect(
                    host=serializer.data['host_id'],
                    user=serializer.data['user_name'],
                    password=serializer.data['password'],
                    database=serializer.data['database_name']
                    )
                print("mydb.is_connected()",mydb.is_connected())
                # Check if the connection is successful
                if mydb.is_connected():
                    # showTable = rb_sql_show_tables(myDBconn=mydb, table_name='customers')

                    return Response('Connected', status=status.HTTP_200_OK)
                else:
                    return Response("Failed",status=status.HTTP_404_NOT_FOUND)
            elif db_type=="Oracle":
                connection_str =f"{serializer.data['user_name']}/{serializer.data['password']}@{serializer.data['host_id']}:{serializer.data['port']}/{serializer.data['service_name_or_SID']}"
                if cx_Oracle.connect(connection_str):
        
                    mydb = cx_Oracle.connect(connection_str)
                    print("mydb",mydb)

                    return Response("Connected", status=status.HTTP_200_OK)
                else:
                    return Response("Failed",status=status.HTTP_404_NOT_FOUND)
                # return Response('serializer.data', status=status.HTTP_200_OK)
            elif db_type=="Mongo":
                return Response('serializer.data', status=status.HTTP_200_OK)
            else:
                return Response('serializer.data', status=status.HTTP_200_OK)
        except Exception as e:
            # Handle any database connection errors
            return Response(f'Database connection error: {str(e)}', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # serializer.save()
        # return Response('serializer.data', status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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
                "connection_name": 0,
                "database_name": 1,
                "database_type": 2,
                "user_name": 3,
                "password": 4,
                "host_id": 5,
                "port": 6, 
                "service_name_or_SID": 7,
            }

            # Sort the data based on the field order
            sorted_data = sorted(data, key=lambda item: field_order.get(list(item.keys())[0], float('inf')))

            return sorted_data
    
        # Order the data
        ordered_data = order_data(data)

        # Print the ordered data
        # print("ordered_data",ordered_data)

        return Response(ordered_data, status=status.HTTP_404_NOT_FOUND)

# UPDATE
@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_rb_db_connect_table(request, id):
    item = rb_db_connect_table.objects.get(id=id)
    # print(request.data)

    serializer = rb_db_connect_table_serializer(instance=item, data=request.data)
    all_serializer_fields = list(serializer.fields.keys())

    # print("all_serializer_fields",all_serializer_fields)

    # Fields to exclude
    fields_to_exclude = ['id', 'created_by', 'last_updated_by', 'created_date']

    # Remove the excluded fields from the list of field names
    required_serializer_fields = [field for field in all_serializer_fields if field not in fields_to_exclude]

    # print("required_serializer_fields",required_serializer_fields)

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    else:
        error_data = serializer.errors
        # print("error_data", error_data, len(error_data))
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
                "connection_name": 0,
                "database_name": 1,
                "database_type": 2,
                "user_name": 3,
                "password": 4,
                "host_id": 5,
                "port": 6, 
                "service_name_or_SID": 7,
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
# @permission_classes([IsAuthenticated])
def del_rb_db_connect_table(request, id):
    item = rb_db_connect_table.objects.get(id=id)
    data = request.data

    if item.delete_flag != data["delete_flag"]:
        item.delete_flag = data["delete_flag"]

    item.save()
    serializer = rb_db_connect_table_serializer(item)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_countries(request, id=0):
    if id == 0:
        country = countries.objects.filter(delete_flag="N")
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




def fun_compData(data, value_type, kpiid, cid, luid):
    Del_serializer = computation_details.objects.filter(kpi_id=kpiid)
    Del_serializer.delete()
    Tempdata = {
            "computation_logic": data["computation_logic"] if data["computation_logic"] else '',
            "filter_condition": data["filter_condition"] if data["filter_condition"] else '',
            "value_type": value_type if value_type else '',
            "period_column": data["period_column"] if data["period_column"] else '',
            "url": data["url"] if data["url"] else '',
            "user_name": data["user_name"] if data["user_name"] else '',
            "Password": data["Password"] if data["Password"] else '',
            "kpi_id": kpiid,
            "created_by": cid,
            "last_updated_by": luid,
        }
    serializer = computation_details_serailizer(data=Tempdata)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    else:
        print("else", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def split_url(url):
    parse_object = urlparse(url)
    path_segments = parse_object.path.split('/')
    base_name = f"{parse_object.scheme}://{parse_object.netloc}/"
    
    # If there are at least 3 segments, combine the first three
    if len(path_segments) > 2:
        base_name += "/".join(path_segments[1:3]) + '/'
        remainder_path = "/".join(path_segments[3:])
    else:
        remainder_path = "/".join(path_segments[1:])
        

    fileExtension = remainder_path.split(".")[-1]
    
    return base_name, remainder_path, fileExtension
@api_view(["PUT"])
# @permission_classes([IsAuthenticated])
def get_sharepointData(request):
    data = request.data
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "file_warehouse", "shared_file.xlsx")
    try:
        Rooturl, server_relative_url, fileExtension = split_url(data['url'])
        if fileExtension != 'xlsx' and fileExtension != 'csv':
            return Response({'error': "Given file is either excel or csv"}, status=400)
        
        ctx = ClientContext(Rooturl).with_user_credentials(data['user_name'], data['Password'])
        with open(file_path, "wb") as local_file:
            try:
                file = ctx.web.get_file_by_server_relative_url(server_relative_url)
                file.download(local_file)
                ctx.execute_query()
            except FileNotFoundError:
                return Response({'error': f"File not found at {server_relative_url}"}, status=404)
            except Exception as e:
                error_message = str(e)
                # if "invalid username or password" in error_message.lower():
                #     return Response({'error': 'Invalid credentials provided'}, status=401)
                # else:
                print("error_message -- ", error_message)
                return Response({'error': error_message}, status=500)

        fileData = pd.ExcelFile(local_file.name)
        returnData = {}
        periodColumns = []

        for sheet_name in fileData.sheet_names:
            sheet_details = pd.read_excel(fileData, sheet_name=sheet_name, nrows=5)
            date_columns = sheet_details.select_dtypes(include=['datetime']).columns.tolist()
            periodColumns.extend(date_columns)
            sanitized_data = sheet_details.replace([np.inf, -np.inf, np.nan], None)
            returnData[sheet_name] = sanitized_data
        
        return Response({'tableData':returnData, 'SuggestionData': periodColumns}, status=200)
    except Exception as e:
        print(f"==>> .response.status_code: {e.response.status_code}")
        return JsonResponse({'error': e}, status=500)    


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_computational_details(request, id=0):
    try:
        if id == 0:
            Comp = computation_details.objects.filter(delete_flag="N")
        else:
            Comp = computation_details.objects.filter(id=id)
    
        serializer = computation_details_serailizer(Comp, many=True)
    except Exception:
        print(Exception)
    return Response(serializer.data)

@api_view(["POST"])
# @permission_classes([IsAuthenticated])
def _search(request):
    print(request.data)
    return Response(status=200)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_kpi_else_org_stop_light_indicators(request, kpi_id):
    org = kpi_stop_light_indicators.objects.filter(delete_flag="N", kpi_id=kpi_id)
    if len(org) == 0:
        org = org_definition_stop_light_indicators.objects.filter(delete_flag="N")
        serializer = org_definition_stop_light_indicators_serializer(org, many=True)
    else:
        org = kpi_stop_light_indicators.objects.filter(kpi_id=kpi_id, delete_flag="N")
        serializer = kpi_stop_light_indicators_serializer(org, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)