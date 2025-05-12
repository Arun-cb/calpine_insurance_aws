from django.db import models
from django.contrib.auth.models import User, Group
from django.core.validators import MaxValueValidator, MinValueValidator
from django.core.exceptions import ValidationError
import datetime

# License Validity
class user_license(models.Model):
    license_key = models.CharField(max_length=50, null=False, blank=False)
    user_id = models.IntegerField(null=True, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_user_license"
        
# SMTP Mail
class smtp_configure(models.Model):
    user_id = models.IntegerField(null=False, blank=False)
    server_name = models.CharField(max_length=300, null=False, blank=False)
    username = models.CharField(max_length=300, null=False, blank=False)
    password = models.CharField(max_length=300, null=False, blank=False)
    protocol = models.CharField(max_length=300, null=False, blank=False)
    port = models.IntegerField(null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_smtp_configure"
        
# Session 
class session(models.Model):
    id = models.AutoField(primary_key=True)
    uid = models.IntegerField(null=False, blank=False)
    sid = models.CharField(max_length=455, null=False, blank=False)
    logintime = models.CharField(max_length=20, null=True, blank=True)
    lasttime = models.CharField(max_length=20, null=True, blank=True)
    expired = models.CharField(max_length=20, null=False, blank=False)
    status = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tb_sc_session"

# Session Configuration
class session_configuration(models.Model):
    idle_time = models.IntegerField(null=False, blank=False)
    session_time = models.IntegerField(null=False, blank=False)
    created_by = models.IntegerField(null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=True, blank=True)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_session_configuration"

# SSO Config
class sso_configure(models.Model):

    app_id = models.CharField(max_length=300, null=False, blank=False)
    tenant_id = models.CharField(max_length=300, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_sso_configure"


# System Audit Table

# Identity (A running #)
# Windowname
# TableName
# ColumnName
# Action (New/Modified/Deleted)
# PreviousValue
# CurrentValue
# Updated User
# Updated Time

class SystemAuditLog(models.Model):  
    windowname = models.CharField(max_length=255, null=False, blank=False)  # Always specify max_length
    table_name = models.CharField(max_length=255, null=False, blank=False)  # Use snake_case for fields
    record_id = models.PositiveIntegerField(null=False, blank=False)  # Add this to track which row was modified
    # column_name = models.CharField(max_length=255, null=False, blank=False)
    action = models.CharField(max_length=10, choices=[
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete')
    ], null=False, blank=False)
    previous_value = models.TextField(null=True, blank=True)
    current_value = models.TextField(null=True, blank=True)
    last_updated_by = models.IntegerField(null=True, blank=True)
    last_updated_date = models.DateTimeField(auto_now_add=True)  # auto_now_add for creation timestamp

    class Meta:
        db_table = "tb_sc_system_audit_log"
        indexes = [
            models.Index(fields=['table_name', 'record_id']),
            models.Index(fields=['last_updated_date']),
        ]

# User Profile Picture function
def profile_pic_upload_path(instance, filename):
    obj = user_profile.objects.all().last()
    ext = filename.split('.')
    if obj == None:
        file_name = "user_profile_%s.%s" % (1, ext[1])
    elif instance.id == None:
        file_name = "user_profile_%s.%s" % (obj.id+1, ext[1])
    else:
        file_name = "user_profile_%s_upd.%s" % (instance.id, ext[1])
    return file_name
        
# User Profile

class user_profile(models.Model):
    user_id = models.ForeignKey(
        User, null=False, blank=False, db_column='user_id', on_delete=models.CASCADE)
    profile_pic = models.ImageField(null=True, blank=True, upload_to=profile_pic_upload_path)
    temporary_address = models.CharField(max_length=100, null=True, blank=True)
    permanent_address = models.CharField(max_length=100, null=True, blank=True)
    contact = models.CharField(max_length=10,null=True, blank=True)
    user_group = models.CharField(max_length=100, null=False, blank=False)
    user_region = models.CharField(max_length=100, null=False, blank=False, default='all')
    user_status = models.BooleanField(default=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_user_profile"

        
# Organization definition

class org_definition(models.Model):
    organization_name = models.CharField(
        max_length=300, null=False, blank=False)
    address_1 = models.CharField(max_length=300, null=False, blank=False)
    address_2 = models.CharField(max_length=300, null=True, blank=True)
    city = models.CharField(max_length=50, null=False, blank=False)
    country = models.CharField(max_length=50, null=False, blank=False)
    state = models.CharField(max_length=50, null=False, blank=False)
    no_of_org_functional_levels = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(10)], null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_org_definition"

# Stop Light Indicators Org Definition

class org_definition_stop_light_indicators(models.Model):
    stop_light_indicator_from = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=False, blank=False)
    stop_light_indicator_to = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=False, blank=False)
    stop_light_indicator = models.CharField(
        max_length=50, null=False, blank=False)
    def_id = models.ForeignKey(
        org_definition, null=False, blank=False, on_delete=models.CASCADE, db_column='def_id')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_org_definition_stop_light_indicators"

# Organization Functional Level

class org_functional_level(models.Model):
    hierarchy_level = models.IntegerField(null=False, blank=False)
    hierarchy_name = models.CharField(max_length=300, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_org_functional_level"
        
# Org Functional Hierarchy

class org_functional_hierarchy(models.Model):
    functional_level_id = models.AutoField(primary_key=True)
    functional_level_code = models.CharField(
        max_length=300, null=False, blank=False)
    # hierarchy_level = models.IntegerField(null=False, blank=False)
    hierarchy_level = models.ForeignKey(
        org_functional_level, null=False, blank=False, db_column='hierarchy_level', on_delete=models.CASCADE)
    parent_level_id = models.IntegerField(null=False, blank=False)
    main_parent_id = models.IntegerField(null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_org_functional_hierarchy"

class navigation_menu_details(models.Model):
    menu_id = models.AutoField(primary_key=True)
    menu_name = models.CharField(
        max_length=300, null=False, blank=False, unique=True)
    parent_menu_id = models.IntegerField(null=False, blank=False)
    url = models.CharField(max_length=300, null=False, blank=False)
    page_number = models.IntegerField(null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_navigation_menu_details"

# User Menu Access

class user_access_definition(models.Model):
    menu_id = models.ForeignKey(
        navigation_menu_details, max_length=5, null=False, blank=False, db_column='menu_id', on_delete=models.CASCADE)
    user_id = models.ForeignKey(
        User, related_name='user', null=False, blank=False, db_column='user_id', on_delete=models.CASCADE)
    add = models.CharField(max_length=1, null=False, blank=False, default='N')
    edit = models.CharField(max_length=1, null=False, blank=False, default='N')
    view = models.CharField(max_length=1, null=False, blank=False, default='N')
    delete = models.CharField(max_length=1, null=False,
                              blank=False, default='N')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_user_access_definition"

# Group Menu Access

class group_access_definition(models.Model):
    menu_id = models.ForeignKey(
        navigation_menu_details, max_length=5, null=False, blank=False, db_column='menu_id', on_delete=models.CASCADE)
    group_id = models.ForeignKey(
        Group, related_name='group', null=False, blank=False, db_column='group_id', on_delete=models.CASCADE)
    add = models.CharField(max_length=1, null=False, blank=False, default='N')
    edit = models.CharField(max_length=1, null=False, blank=False, default='N')
    view = models.CharField(max_length=1, null=False, blank=False, default='N')
    delete = models.CharField(max_length=1, null=False,
                              blank=False, default='N')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_group_access_definition"
        
# Chart Attributes


class chart_attributes(models.Model):
    user_id = models.IntegerField(null=False, blank=False)
    chart_type = models.CharField(max_length=300, null=False, blank=False)
    component = models.CharField(max_length=300, null=False, blank=False)
    attr_name = models.CharField(max_length=300, null=False, blank=False)
    attr_key = models.CharField(max_length=300, null=False, blank=False)
    attr_value = models.CharField(max_length=300, null=False, blank=False)
    user_attr_name = models.CharField(max_length=300, null=False, blank=False)
    default_attr_value = models.CharField(
        max_length=300, null=False, blank=False)
    min = models.CharField(max_length=300, null=False, blank=False)
    max = models.CharField(max_length=300, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_chart_attributes"

# Chart Attributes Options


class chart_attributes_options(models.Model):
    attr_name = models.CharField(max_length=300, null=False, blank=False)
    attr_key = models.CharField(max_length=300, null=False, blank=False)
    attr_types = models.CharField(max_length=300, null=False, blank=False)
    attr_options = models.CharField(max_length=300, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_chart_attributes_options"


class compliance_details(models.Model):
    id = models.AutoField(primary_key=True)
    compliance_group_name = models.CharField(max_length=50, null=False, blank=False)
    compliance_name = models.TextField(null=False, blank=False) # No need for max_length
    compliance_criteria = models.CharField(max_length=50, null=False, blank=False)
    compliance_value = models.TextField(null=False, blank=False) # No need for max_length
    value_type = models.CharField(max_length=255, null=False, blank=False, default='nill')
    option_type = models.CharField(max_length=255, null=True, blank=True, default='nill')
    effective_from = models.DateTimeField(auto_now=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_compliance_details"
        
        
# Config Codes
class config_codes(models.Model):
    config_type = models.CharField(max_length=500, null=False, blank=False)
    config_code = models.CharField(max_length=500, null=False, blank=False)
    config_value = models.CharField(max_length=500, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_admindata = models.BooleanField(default=False)
    # CharField(max_length=10, null=False, blank=False)

    class Meta:
        constraints = [
            # models.UniqueConstraint(
            #     fields=['config_type', 'config_code'], name='unique_config_type_config_code')
        ]
        db_table = "tb_sc_config_codes"
        
def upload_path(instance, filename):
    obj = settings.objects.all().last()
    ext = filename.split('.')
    if obj == None:
        file_name = "settings_logo_%s.%s" % (1, ext[1])
    elif instance.id == None:
        file_name = "settings_logo_%s.%s" % (obj.id+1, ext[1])
    else:
        file_name = "settings_logo_%s_upd.%s" % (instance.id, ext[1])
    # print(file_name)
    return file_name
    # '/'.join([file_name])
               
# Settings
class settings(models.Model):
    variable_name = models.CharField(max_length=300, null=False, blank=False)
    value = models.CharField(max_length=30, null=False, blank=False)
    types = models.CharField(max_length=30, null=True, blank=True)
    hours = models.CharField(max_length=30, null=True, blank=True)
    seconds = models.CharField(max_length=30, null=True, blank=True)
    ampm = models.CharField(max_length=5, null=True, blank=True)
    user_id = models.IntegerField(null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    logo = models.ImageField(null=True, blank=True, upload_to=upload_path)

    class Meta:
        db_table = "tb_sc_settings"
        
# Global helper
class helper(models.Model):
    page_no = models.ForeignKey(navigation_menu_details, null=False,
                                blank=False, db_column='page_no', on_delete=models.CASCADE)
    label = models.CharField(max_length=500, null=False, blank=False)
    help_context = models.CharField(max_length=500, null=False, blank=False)
    context_order = models.IntegerField()
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tb_sc_helper"
        
# Validation Warnings
class warnings(models.Model):
    error_code = models.CharField(max_length=50, null=False, blank=False)
    error_msg = models.CharField(max_length=500, null=False, blank=False)
    error_category = models.CharField(max_length=50, null=False, blank=False)
    error_from = models.CharField(max_length=50, null=False, blank=False)
    error_no = models.IntegerField(null=True, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tb_sc_warnings"
    
# Counteries
class countries(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, null=True, blank=True)
    iso3 = models.CharField(max_length=10, null=True, blank=True)
    iso2 = models.CharField(max_length=10, null=True, blank=True)
    numeric_code = models.CharField(max_length=10, null=True, blank=True)
    capital = models.CharField(max_length=50, null=True, blank=True)
    currency = models.CharField(max_length=10, null=True, blank=True)
    currency_name = models.CharField(max_length=50, null=True, blank=True)
    currency_symbol = models.CharField(max_length=10, null=True, blank=True)
    phonecode = models.CharField(max_length=20, null=True, blank=True)
    region = models.CharField(max_length=20, null=True, blank=True)
    region_id = models.IntegerField(null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_countries"

# States
class states(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, null=True, blank=True)
    iso2 = models.CharField(max_length=10, null=True, blank=True)
    country_id = models.ForeignKey(
        countries, null=False, blank=False, db_column='country_id', on_delete=models.CASCADE)
    created_date = models.DateTimeField(auto_now_add=True, null=True)
    last_updated_date = models.DateTimeField(auto_now=True, null=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_states"

# Compliance Code
class compliance_codes(models.Model):
    compliance_type = models.CharField(max_length=500, null=False, blank=False)
    compliance_code = models.CharField(max_length=500, null=False, blank=False)
    compliance_value = models.CharField(max_length=500, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_header = models.BooleanField(default=False)

    class Meta:
        constraints = [
            # models.UniqueConstraint(
            #     fields=['config_type', 'config_code'], name='unique_config_type_config_code')
        ]
        db_table = "tb_sc_compliance_codes"
        
class counterparty_profile(models.Model):
    entity_type = models.CharField(max_length=300, null=False, blank=False)
    name = models.CharField(max_length=300, null=False, blank=False, unique=True)
    address = models.CharField(max_length=300, null=True, blank=True)
    city_postal_code = models.CharField(max_length=50, null=False, blank=False)
    country = models.CharField(max_length=50, null=False, blank=False)
    state = models.CharField(max_length=50, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    
    class Meta:
        db_table = "tb_sc_counterparty_profile"
    
class plant_details(models.Model):
    name = models.CharField(max_length=300, null=False, blank=False, unique=True)
    code = models.CharField(max_length=300, null=False, blank=False)
    region = models.CharField(max_length=300, null=True, blank=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    
    class Meta:
        db_table = "tb_sc_plant_details"
        
# Counterparty Details

# Custom validator for year
def validate_year(value):
    current_year = datetime.date.today().year
    if value < 1900 or value > current_year:
        raise ValidationError(f'{value} is not a valid year.')

class counterparty_details(models.Model):
    # level_id = models.ForeignKey(
    #     org_functional_hierarchy, null=False, blank=False, db_column='level_id', on_delete=models.CASCADE)
    region_id = models.CharField(max_length=100, null=False, blank=False, default='none')
    level_id = models.CharField(max_length=50, null=True, blank=True)
    # Set ForeignKey to counterparty_profile using the name field
    party_name = models.ForeignKey(
        counterparty_profile, null=False, blank=False, db_column='party_name', 
        on_delete=models.CASCADE)  # Linking name field
    start_date = models.DateTimeField()
    # Set ForeignKey to plant_details using the name field
    plant = models.ForeignKey(
        plant_details, null=False, blank=False, db_column='plant', 
        on_delete=models.CASCADE)  # Linking name field
    subject = models.CharField(max_length=500, null=False, blank=False)
    expiry_date = models.DateTimeField()
    year = models.PositiveIntegerField(
        validators=[validate_year],
        help_text="Enter a valid year between 1900 and current year."
    )
    reference = models.CharField(max_length=500, null=False, blank=False)
    term = models.CharField(max_length=500, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    
    class Meta:
        db_table = "tb_sc_counterparty_details"
        
# Compliance Actuals 
class compliance_actuals(models.Model):
    compliance_id = models.ForeignKey(
        compliance_details, null=False, blank=False, db_column='compliance_id', on_delete=models.CASCADE)
    counterparty_id = models.ForeignKey(
        counterparty_details, null=False, blank=False, db_column='counterparty_id', on_delete=models.CASCADE)
    actuals = models.CharField(max_length=500, null=True, blank=True)
    attachment = models.CharField(max_length=50, null=False, blank=False)
    path = models.CharField(max_length=255, null=False, blank=False)
    file_name = models.CharField(max_length=100, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    
    class Meta:
        db_table = "tb_sc_compliance_actuals"



class FileStore(models.Model):
    Counterparty_id = models.ForeignKey(
        counterparty_details, null=False, blank=False, db_column='compliance_id', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    file = models.BinaryField()
    content_type = models.CharField(max_length=100, null=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_filestore"


class initiative(models.Model):
    counterparty_id = models.ForeignKey(
        counterparty_details, null=False, blank=False, db_column='counterparty_id', on_delete=models.CASCADE)
    compliance_id = models.ForeignKey(
        compliance_details, null=False, blank=False, db_column='compliance_id', on_delete=models.CASCADE)
    action_item = models.CharField(max_length=500, null=False, blank=False)
    target_date = models.DateTimeField(null=False, blank=False)
    ownership = models.CharField(max_length=100, null=False, blank=False)
    status = models.CharField(max_length=20, null=False, blank=False)
    comments = models.CharField(max_length=500, null=True, blank=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_initiative"
        
# Compliance Indicators

class compliance_indicators(models.Model):
    compliance_indicator_from = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=False, blank=False)
    compliance_indicator_to = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=False, blank=False)
    compliance_indicator = models.CharField(
        max_length=50, null=False, blank=False)
    # def_id = models.ForeignKey(
    #     org_definition, null=False, blank=False, on_delete=models.CASCADE, db_column='def_id')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sc_compliance_indicators"
        
class block_details(models.Model):
    name = models.CharField(max_length=300, null=False, blank=False, unique=True)
    code = models.CharField(max_length=300, null=False, blank=False)
    active = models.BooleanField(default=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.BooleanField(default=False)
    
    class Meta:
        db_table = "tb_sc_block_details"