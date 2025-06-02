from rest_framework import serializers
from base.models import *
from django.contrib.auth.models import User, Group
from rest_framework.validators import UniqueValidator, UniqueTogetherValidator
from django.contrib.auth.password_validation import validate_password


# SMPT Password
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
        )

        user.set_password(validated_data['password'])
        user.save()

        return user

# Update 
class UpdateActiveSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('is_active',)

    def update(self, instance, validated_data):
        instance.is_active = validated_data['is_active']
        instance.save()

        return instance

# user serialzer
class user_serializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email',
                  'first_name', 'last_name', 'is_active')
        
# User Serialzer
class group_serializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name')
        
# Auth Group
class auth_group_serializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('id', 'name')

# Join group and group_access_definition table
class group_group_access_serializer(serializers.ModelSerializer):
    group_id = group_serializer(read_only=True)

    class Meta:
        model = group_access_definition
        fields = ['group_id', 'menu_id', 'group_id', 'add', 'view',
                  'edit', 'delete', 'created_by', 'last_updated_by']
        
# SMTP
class smtp_configure_serializer(serializers.ModelSerializer):
    class Meta:
        model = smtp_configure
        fields = ('id', 'user_id', 'server_name', 'username', 'password',
                  'protocol', 'port', 'created_by', 'last_updated_by')
        
class CheckAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'is_superuser', 'is_staff', 'is_active',)

# License
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

# SSO
class sso_configure_serializer(serializers.ModelSerializer):
    class Meta:
        model = sso_configure
        fields = ('id', 'app_id', 'tenant_id', 'created_by', 'last_updated_by')
        
# User Profile
class user_profile_serializer(serializers.ModelSerializer):
    class Meta:
        model = user_profile
        fields = ('id', 'user_id', 'profile_pic', 'temporary_address', 'permanent_address', 'contact', 'user_group', 'user_region', 'user_status', 'created_by', 'last_updated_by', 'delete_flag')
        
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
        
# Compliance Details
class compliance_details_serializer(serializers.ModelSerializer):
    class Meta:
        model = compliance_details
        fields = ('id', 'compliance_group_name','compliance_name','compliance_criteria', 'compliance_value', 'value_type', 'option_type', 'effective_from', 'created_by', 'last_updated_by')

# Config codes Serializer
class config_codes_serializer(serializers.ModelSerializer):
    class Meta:
        model = config_codes
        fields = ('id', 'config_type', 'config_code', 'config_value',
                  'created_by', 'last_updated_by', 'is_active', 'is_admindata')
        validators = [
            UniqueTogetherValidator(
                queryset=config_codes.objects.all(),
                fields=['config_type', 'config_code'],
                message=(
                    "The Fields Config Type, Config Code must make a unique set.")
            )
        ]
        
# Compliance Actuals and details
class compliance_actuals_and_details_serializer(serializers.ModelSerializer):
    compliance_id = compliance_details_serializer(read_only=True)
    class Meta:
        model = compliance_actuals
        fields = ('id', 'compliance_id', 'counterparty_id', 'actuals', 'attachment', 'path', 'file_name', 'created_by', 'last_updated_by')

# Compliance Actuals 
class compliance_actuals_serializer(serializers.ModelSerializer):
    class Meta:
        model = compliance_actuals
        fields = ('id', 'compliance_id', 'counterparty_id', 'actuals', 'attachment', 'path', 'file_name', 'created_by', 'last_updated_by', 'delete_flag')
        
# CounterParty Details
class counterparty_details_serializer(serializers.ModelSerializer):
    # counterparty_id = compliance_actuals_serializer(read_only=True)
    class Meta:
        model = counterparty_details
        fields = ('id', 'region_id', 'level_id', 'party_name', 'start_date', 'plant', 'subject', 'expiry_date', 'year', 
                  'reference', 'term', 'created_by', 'last_updated_by')

# Settings   
class settings_serializer(serializers.ModelSerializer):
    class Meta:
        model = settings
        fields = '__all__'
        
# Global helper serializer

class helper_serializer(serializers.ModelSerializer):
    class Meta:
        model = helper
        fields = ('id', 'page_no', 'label', 'help_context',
                  'context_order')
        
# Validation warnings serializer
class warnings_serializer(serializers.ModelSerializer):
    class Meta:
        model = warnings
        fields = ('id', 'error_code', 'error_msg', 'error_category',
                  'error_from', 'error_no', 'created_by', 'last_updated_by')
        
class countries_serializer(serializers.ModelSerializer):
    class Meta:
        model = countries
        fields = '__all__'

class state_serializer(serializers.ModelSerializer):
    class Meta:
        model = states
        fields = '__all__'
        
# compliance codes Serializer
class compliance_codes_serializer(serializers.ModelSerializer):
    class Meta:
        model = compliance_codes
        fields = ('id', 'compliance_type', 'compliance_code', 'compliance_value',
                  'created_by', 'last_updated_by', 'is_active', 'is_header')

class counterparty_profile_serializer(serializers.ModelSerializer):
    class Meta:
        model = counterparty_profile
        fields = '__all__'
        
class plant_details_serializer(serializers.ModelSerializer):
    class Meta:
        model = plant_details
        fields = '__all__'
        
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

class ChangePasswordForAdminSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    confirmpassword = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('password', 'confirmpassword')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirmpassword']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def update(self, instance, validated_data):

        instance.set_password(validated_data['password'])
        instance.save()

        return instance

class FileStoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileStore
        fields = ['id', 'name', 'file', 'content_type', 'Counterparty_id', 'created_by', 'last_updated_by']

class initiative_serializer(serializers.ModelSerializer):
    class Meta:
        model = initiative
        fields= '__all__'

# Compliance Indicators
class compliance_indicators_serializer(serializers.ModelSerializer):
    class Meta:
        model = compliance_indicators
        fields = ('id', 'compliance_indicator_from', 'compliance_indicator_to',
                  'compliance_indicator', 'created_by', 'last_updated_by', 'delete_flag')

# Block Details
class block_details_serializer(serializers.ModelSerializer):
    class Meta:
        model = block_details
        fields = '__all__'
        

class counterparty_actuals_serializer(serializers.ModelSerializer):
    counterparty_id = compliance_actuals_serializer(read_only=True)
    class Meta:
        model = counterparty_details
        fields = ('id', 'region_id', 'level_id', 'party_name', 'start_date', 'plant', 'subject', 'expiry_date', 'year', 
                  'reference', 'term', 'created_by', 'last_updated_by','counterparty_id')