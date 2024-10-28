from numpy import source
from rest_framework import serializers
from base.models import *
from django.contrib.auth.models import User, Group
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueTogetherValidator


class ChangePasswordSerializer(serializers.ModelSerializer):
    # password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                {"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):

        instance.set_password(validated_data['password'])
        instance.save()

        return instance


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'password2',
                  'email', 'first_name', 'last_name', 'is_active')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=validated_data['is_active']
            # is_active=validated_data['is_active']
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class UpdateActiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('is_active',)

    def update(self, instance, validated_data):
        instance.is_active = validated_data['is_active']
        instance.save()

        return instance

# Auth Group


class auth_group_serializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name')

# Org Definition


class org_definition_serializer(serializers.ModelSerializer):
    class Meta:
        model = org_definition
        fields = ('id', 'organization_name', 'address_1', 'address_2', 'city', 'country','state',
                  'no_of_org_functional_levels', 'created_by', 'last_updated_by', 'delete_flag')

# Stop Light Indicators


class org_definition_stop_light_indicators_serializer(serializers.ModelSerializer):
    class Meta:
        model = org_definition_stop_light_indicators
        fields = ('id', 'stop_light_indicator_from', 'stop_light_indicator_to',
                  'stop_light_indicator', 'def_id', 'created_by', 'last_updated_by', 'delete_flag')


# Organization Functional Level
class org_functional_level_serializer(serializers.ModelSerializer):
    class Meta:
        model = org_functional_level
        fields = ('id', 'hierarchy_level', 'hierarchy_name',
                  'created_by', 'last_updated_by')

# Currencies Serializer


class currencies_serializer(serializers.ModelSerializer):
    class Meta:
        model = currencies
        fields = ('id', 'currency_code', 'currency_name', 'sign',
                  'created_by', 'last_updated_by', 'created_date')


# Organization Settings
class org_settings_serializer(serializers.ModelSerializer):
    # reporting_currency = serializers.SlugRelatedField(read_only=True,slug_field="currency_code")

    class Meta:
        model = org_settings
        fields = ('id', 'fiscal_year_start', 'week_start', 'logo', 'reporting_currency',
                  'number_format_decimals', 'number_format_comma_seperator', 'created_by', 'last_updated_by')


# Org Functional Hierarchy
class org_functional_hierarchy_serializer(serializers.ModelSerializer):
    class Meta:
        model = org_functional_hierarchy
        fields = ('functional_level_id', 'functional_level_code', 'hierarchy_level',
                  'parent_level_id', 'main_parent_id', 'created_by', 'last_updated_by')

# navigation_menu_details


class navigation_menu_details_serializer(serializers.ModelSerializer):
    class Meta:
        model = navigation_menu_details
        fields = ('menu_id', 'menu_name', 'parent_menu_id',
                  'url', 'page_number', 'created_by', 'last_updated_by')


# user_access_definition
class user_access_definition_serializer(serializers.ModelSerializer):
    class Meta:
        model = user_access_definition
        fields = ('menu_id', 'user_id', 'add', 'edit', 'view',
                  'delete', 'created_by', 'last_updated_by')

# group_access_definition


class group_access_definition_serializer(serializers.ModelSerializer):
    class Meta:
        model = group_access_definition
        fields = ('menu_id', 'group_id', 'add', 'edit', 'view',
                  'delete', 'created_by', 'last_updated_by')

# join ORM for menu


class nav_menu_serial(serializers.ModelSerializer):
    class Meta:
        model = navigation_menu_details
        # fields = '__all__'
        fields = ('menu_id', 'menu_name', 'parent_menu_id',
                  'url', 'page_number', 'created_by', 'last_updated_by')


class user_access_serail(serializers.ModelSerializer):
    menu_id = nav_menu_serial(read_only=True)

    class Meta:
        model = user_access_definition
        # fields = '__all__'
        fields = ['menu_id', 'user_id', 'add', 'edit',
                  'view', 'delete', 'created_by', 'last_updated_by']


# group access serializer
class group_access_serail(serializers.ModelSerializer):
    menu_id = nav_menu_serial(read_only=True)

    class Meta:
        model = group_access_definition
        # fields = '__all__'
        fields = ['menu_id', 'group_id', 'add', 'edit',
                  'view', 'delete', 'created_by', 'last_updated_by']

        # Config codes Serializer


class config_codes_serializer(serializers.ModelSerializer):
    class Meta:
        model = config_codes
        fields = ('id', 'config_type', 'config_code', 'config_value',
                  'created_by', 'last_updated_by', 'is_active')
        validators = [
            UniqueTogetherValidator(
                queryset=config_codes.objects.all(),
                fields=['config_type', 'config_code'],
                message=(
                    "The Fields Config Type, Config Code must make a unique set.")
            )
        ]

# uom


class uom_serializer(serializers.ModelSerializer):
    class Meta:
        model = uom_masters
        fields = ('id', 'uom_code', 'description',
                  'created_by', 'last_updated_by')

# user serialzer


class user_serializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email',
                  'first_name', 'last_name', 'is_active')


# user serialzer
class group_serializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name')

# Join user and user_access_definition table


class user_user_access_serializer(serializers.ModelSerializer):
    user_id = user_serializer(read_only=True)
    # print(user)

    class Meta:
        model = user_access_definition
        fields = ['user_id', 'menu_id', 'user_id', 'add', 'view',
                  'edit', 'delete', 'created_by', 'last_updated_by']


# Join group and group_access_definition table
class group_group_access_serializer(serializers.ModelSerializer):
    group_id = group_serializer(read_only=True)
    # print(user)

    class Meta:
        model = group_access_definition
        fields = ['group_id', 'menu_id', 'group_id', 'add', 'view',
                  'edit', 'delete', 'created_by', 'last_updated_by']


# Perspectives Serializer
class perspectives_serializer(serializers.ModelSerializer):
    class Meta:
        model = perspectives
        fields = ('id', 'perspective_code', 'perspective',
                  'description', 'created_by', 'last_updated_by')

# scorecard


class scorecard_serializer(serializers.ModelSerializer):
    class Meta:
        model = scorecard
        fields = ('id', 'scorecard_description', 'functional_hierarchy_level',
                  'from_date', 'to_date', 'publish_flag', 'created_by', 'last_updated_by')

# scorecard Details


class scorecard_details_serializer(serializers.ModelSerializer):
    class Meta:
        model = scorecard_details
        fields = ('id', 'scorecard_id', 'perspective_id',
                  'weight', 'weight_editable', 'created_by', 'last_updated_by')
        # validators = [
        #     UniqueTogetherValidator(
        #         queryset=scorecard_details.objects.all(),
        #         fields=['scorecard_id', 'perspective_id'],
        #         message=(
        #             "The Fields scorecard_id, perspective_id must make a unique set.")
        #     )
        # ]

# class perspective_with_scorecard_serializer(serializers.ModelSerializer):
#     perspective_id = perspectives_serializer(many=True)
#     class Meta:
#         model=scorecard_details
#         fields = ('scorecard_id','perspective_id')


class perspective_with_scorecard_serializer(serializers.ModelSerializer):
    perspective_id = perspectives_serializer(read_only=True)
    # print(user)

    class Meta:
        model = scorecard_details
        fields = ['id', 'perspective_id']


# Bussiness goals/Objectives Serializer
class business_goals_objectives_serializer(serializers.ModelSerializer):
    class Meta:
        model = business_goals_objectives
        fields = ('id', 'scorecard_id', 'scorecard_details_id', 'objective_code',
                  'objective_description', 'weight', 'weight_editable', 'created_by', 'last_updated_by')

        # validators = [
        #     UniqueTogetherValidator(
        #         queryset=business_goals_objectives.objects.all(),
        #         fields=['scorecard_id',
        #                 'scorecard_details_id', 'objective_code'],
        #         message=(
        #             "The Fields scorecard_id,scorecard_details_id , objective_code must make a unique set.")
        #     )
        # ]


# user_access_definition
class settings_serializer(serializers.ModelSerializer):
    class Meta:
        model = settings
        fields = '__all__'
        # fields = ('variable_name', 'value', 'types', 'hours', 'seconds', 'ampm', 'user_id',
        #           'created_by', 'last_updated_by')


# KPI Serializer
class kpi_details_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_details
        fields = ('id', 'perspective_id', 'objective_id', 'scorecard_details_id', 'scorecard_id', 'kpi_code', 'kpi', 'ytd', 'frequency', 'period_type', 'weight', 'weight_editable', 'measure',
            'baseline', 'target', 'min', 'max', 'optimization', 'chart_type', 'actual_type', 'created_by', 'last_updated_by', 'created_date')
        # 'performance','score',
        # validators = [
        #     UniqueTogetherValidator(
        #         queryset=kpi_details.objects.all(),
        #         fields=['perspective_id', 'objective_id',
        #                 'scorecard_id', 'kpi_code'],
        #         message=(
        #             "The Fields Perspective Id, Objective Id,Scorecard Id,KPI Code must make a unique set.")
        #     )
        # ]


# KPI Actual Serializer
class kpi_actuals_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_actuals
        fields = ('id', 'scorecard_id', 'perspective_id', 'objective_id', 'kpi_id', 'period',
                  'actuals', 'actuals_date', 'actuals_boolean', 'summery', 'created_by', 'last_updated_by')

# Stop Light Indicators Scorecard KPI


class kpi_stop_light_indicators_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_stop_light_indicators
        fields = ('id', 'stop_light_indicator_from', 'stop_light_indicator_to',
                  'stop_light_indicator', 'kpi_id', 'created_by', 'last_updated_by', 'delete_flag')


# KPI View Serializer
# class kpi_view_serializer(serializers.ModelSerializer):
#     class Meta:
#         model = kpi_view
#         fields = '__all__'

# KPI Dashboard View Serializer


# class kpi_dashboard_view_serializer(serializers.ModelSerializer):
#     class Meta:
#         model = kpi_dashboard_view
#         fields = '__all__'

# Objective Dashboard View Serializer


# class obj_dashboard_view_serializer(serializers.ModelSerializer):
#     class Meta:
#         model = obj_dashboard_view
#         fields = '__all__'

# Scorecard Details Dashboard View Serializer


# class sd_dashboard_view_serializer(serializers.ModelSerializer):
#     class Meta:
#         model = sd_dashboard_view
#         fields = '__all__'

# ScoreCard Dashboard View Serializer


# class sc_dashboard_view_serializer(serializers.ModelSerializer):
#     class Meta:
#         model = sc_dashboard_view
#         fields = '__all__'


class kpi_actuals_monthly_score_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_actuals_monthly_score
        fields = '__all__'

# class kpi_actuals_monthly_score_2_serializer(serializers.ModelSerializer):
#     class Meta:
#         model= kpi_actuals_monthly_score_2
#         fields = '__all__'

# Kpi User Access


class kpi_user_Access_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_user_access
        fields = ('id', 'user_id', 'kpi_id', 'kpi_owner',
                  'created_by', 'last_updated_by')

# Chart Attributes


class chart_attributes_serializer(serializers.ModelSerializer):
    class Meta:
        model = chart_attributes
        fields = ('id', 'user_id', 'chart_type', 'component', 'attr_name', 'attr_key', 'attr_value',
                  'user_attr_name', 'default_attr_value', 'min', 'max', 'created_by', 'last_updated_by')

 # Chart Attributes Options


class chart_attributes_options_serializer(serializers.ModelSerializer):
    class Meta:
        model = chart_attributes_options
        fields = ('id', 'attr_name', 'attr_key', 'attr_types',
                  'attr_options', 'created_by', 'last_updated_by')


class kpi_pending_actions_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_pending_actions
        fields = ('user_id', 'kpi', 'message', 'show_flag', 'upcoming_date',
                  'kpi_id', 'action', 'created_by', 'last_updated_by', 'last_updated_date')


class temporary_kpi_pending_actions_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_pending_actions
        fields = ('id', 'user_id', 'kpi', 'message', 'show_flag',
                  'upcoming_date', 'kpi_id', 'created_by', 'last_updated_by')


class kpi_sli_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_sli
        fields = ('kpi_id', 'sli_from', 'sli_to', 'sli',
                  'created_by', 'last_updated_by')

# smtp


class smtp_configure_serializer(serializers.ModelSerializer):
    class Meta:
        model = smtp_configure
        fields = ('id', 'user_id', 'server_name', 'username', 'password',
                  'protocol', 'port', 'created_by', 'last_updated_by')


# kpi pin to dashboard
class kpi_pin_dashboard_serializer(serializers.ModelSerializer):
    class Meta:
        model = kpi_pin_dashboard
        fields = ('id', 'kpi_name', 'kpi_score', 'pin_flag',
                  'kpi_id', 'user_id', 'created_by', 'last_updated_by')

# kpi pin dashboard view


# class vw_kpi_pin_dashboard_serializer(serializers.ModelSerializer):
#     class Meta:
#         model = vw_kpi_pin_dashboard
#         fields = '__all__'


class pin_chart_to_homepage_serializer(serializers.ModelSerializer):
    class Meta:
        model = pin_chart_to_homepage
        fields = ('id', 'chart_type', 'kpi_id', 'user_id', 'pin_flag',
                  'order_no', 'created_by', 'last_updated_by')


# ! test serailizer


# class test_serializer(serializers.ModelSerializer):
#     class Meta:
#         model=test_model
#         feilds=('feild1','feild2','feild3')

# ! test serialaizer end

# Kpi score initiative serializer

class initiative_serializer(serializers.ModelSerializer):
    class Meta:
        model = initiative
        fields= '__all__'
        # fields = ('id', 'perspective_id', 'objective_id', 'scorecard_id', 'kpi_id', 'scorecard_description',
        #           'action_item', 'target_date', 'ownership', 'status', 'comments', 'created_by', 'last_updated_by')

# Global helper serializer


class helper_serializer(serializers.ModelSerializer):
    class Meta:
        model = helper
        fields = ('id', 'page_no', 'label', 'help_context',
                  'context_order', 'created_by', 'last_updated_by')

# Validation warnings serializer


class warnings_serializer(serializers.ModelSerializer):
    class Meta:
        model = warnings
        fields = ('id', 'error_code', 'error_msg', 'error_category',
                  'error_from', 'error_no', 'created_by', 'last_updated_by')

# Join kpi


class kpi_details_with_actuals_serializer(serializers.ModelSerializer):
    kpi_id = kpi_details_serializer(read_only=True)

    class Meta:
        model = kpi_actuals
        fields = ('kpi_id', 'period', 'actuals')


class CheckAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'is_superuser', 'is_staff', 'is_active',)


class user_license_serializer(serializers.ModelSerializer):
    class Meta:
        model = user_license
        fields = ('id', 'license_key', 'user_id',
                  'created_by', 'last_updated_by')

# Session

class session_serializer(serializers.ModelSerializer):
    class Meta:
        model = session
        fields = '__all__'


class session_configuration_serializer(serializers.ModelSerializer):
    class Meta:
        model = session_configuration
        fields = '__all__'

# sso


class sso_configure_serializer(serializers.ModelSerializer):
    class Meta:
        model = sso_configure
        fields = ('id', 'app_id', 'tenant_id', 'created_by', 'last_updated_by')


class notification_serializer(serializers.ModelSerializer):
    class Meta:
        model = notification
        fields = '__all__'

        # Join user and user_access_definition table


class notification_and_group_serializer(serializers.ModelSerializer):
    permission = group_serializer(read_only=True)
    # print(user)

    class Meta:
        model = user_access_definition
        fields = ['message', 'permission']


class qb_defnition_serializer(serializers.ModelSerializer):
    class Meta:
        model = query_definition
        fields = '__all__'

class shared_query_definition_serializer(serializers.ModelSerializer):
    class Meta:
        model = shared_query_definition
        fields = '__all__'

class qb_table_serializer(serializers.ModelSerializer):
    class Meta:
        model = query_builder_table
        fields ='__all__'

class qb_table_columns_serializers(serializers.ModelSerializer):
    class Meta:
        model = query_builder_table_columns
        fields ='__all__'

class qb_table_joins_serializers(serializers.ModelSerializer):
    class Meta:
        model = query_builder_table_joins
        fields ='__all__'

class qb_table_alias_serializers(serializers.ModelSerializer):
    class Meta:
        model = query_builder_table_alias
        fields = '__all__'

class qb_table_column_filter_serializers(serializers.ModelSerializer):
    class Meta:
        model = query_builder_table_column_filter
        fields ='__all__'

class qb_table_groupBy_serializers(serializers.ModelSerializer):
    class Meta:
        model = query_builder_table_groupBy
        fields = '__all__'

class qb_table_aggergate_serializers(serializers.ModelSerializer):
    class Meta:
        model = query_builder_aggeration_function_table
        fields ='__all__'

# User pProfile


class user_profile_serializer(serializers.ModelSerializer):
    class Meta:
        model = user_profile
        fields = ('id', 'user_id', 'profile_pic', 'username',
                  'first_name', 'last_name', 'email', 'temporary_address', 'permanent_address', 'contact', 'user_group', 'user_status', 'created_by', 'last_updated_by')

# DB Connect

class rb_db_connect_table_serializer(serializers.ModelSerializer):
    class Meta:
        model = rb_db_connect_table
        fields = ('id', 'connection_name', 'database_name', 'database_type', 'user_name',
                  'password', 'host_id', 'port', 'service_name_or_SID', 'created_by', 'last_updated_by')
        # '__all__'


class scorecard_details_yet_kpi_serializer(serializers.ModelSerializer):
    perspective_id = perspectives_serializer(read_only=True)
    scorecard_id = scorecard_serializer(read_only=True)
    scorecard_details_id = scorecard_details_serializer(read_only=True)
    objective_id = business_goals_objectives_serializer(read_only=True)
    # print(user)

    class Meta:
        model = kpi_details
        fields = ['id','kpi','scorecard_id','scorecard_details_id','perspective_id','objective_id','created_by', 'last_updated_by']
    

class countries_serializer(serializers.ModelSerializer):
    class Meta:
        model = countries
        fields = '__all__'

class state_serializer(serializers.ModelSerializer):
    class Meta:
        model = countries
        fields = '__all__'


class computation_details_serailizer(serializers.ModelSerializer):

    class Meta:
        model = computation_details
        fields = ('id', 'kpi_id', 'period_column', 'drill_down_value', 'computation_logic', 'value_type', 'sheet1', 'sheet2', 'filter_condition', 'no_of_sheets', 'url', 'user_name', 'Password', 'Computation_type', 'created_by', 'last_updated_by')
