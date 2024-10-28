from distutils.command.upload import upload
from re import T
from django.conf import Settings
from django.db import models
from numpy import logical_or
from django.contrib.auth.models import User, Group
from django.core.validators import MaxValueValidator, MinValueValidator
# from datetime import datetime


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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_org_functional_level"

# Currencies


class currencies(models.Model):
    currency_code = models.CharField(max_length=20, null=False, blank=False)
    currency_name = models.CharField(max_length=100, null=False, blank=False)
    sign = models.CharField(max_length=5, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_currencies"

# Organization modesl logo path


def upload_path(instance, filename):
    obj = org_settings.objects.all().last()
    ext = filename.split('.')
    if obj == None:
        file_name = "org_settings_logo_%s.%s" % (1, ext[1])
    elif instance.id == None:
        file_name = "org_settings_logo_%s.%s" % (obj.id+1, ext[1])
    else:
        file_name = "org_settings_logo_%s_upd.%s" % (instance.id, ext[1])
    # print(file_name)
    return file_name
    # '/'.join([file_name])

# Organization Settings


class org_settings(models.Model):
    fiscal_year_start = models.CharField(
        max_length=100, null=False, blank=False)
    week_start = models.CharField(max_length=100, null=False, blank=False)
    logo = models.ImageField(null=False, blank=False, upload_to=upload_path)

    # Forign Key
    reporting_currency = models.ForeignKey(
        currencies, null=False, blank=False, on_delete=models.CASCADE, db_column='reporting_currency')

    number_format_decimals = models.IntegerField(null=False, blank=False)
    number_format_comma_seperator = models.CharField(
        max_length=1, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_org_settings"

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_navigation_menu_details"


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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_user_access_definition"


# group access

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_group_access_definition"


# Config Codes

class config_codes(models.Model):
    config_type = models.CharField(max_length=500, null=False, blank=False)
    config_code = models.CharField(max_length=500, null=False, blank=False)
    config_value = models.CharField(max_length=500, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')
    is_active = models.BooleanField(default=False)
    # CharField(max_length=10, null=False, blank=False)

    class Meta:
        constraints = [
            # models.UniqueConstraint(
            #     fields=['config_type', 'config_code'], name='unique_config_type_config_code')
        ]
        db_table = "tb_sc_config_codes"


class uom_masters(models.Model):
    uom_code = models.CharField(
        max_length=5, null=False, blank=False, unique=True)
    description = models.CharField(max_length=100, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_uom_masters"

 # Perspective Details


class perspectives(models.Model):
    perspective_code = models.CharField(
        max_length=50, null=False, blank=False, unique=True)
    perspective = models.CharField(max_length=100, null=False, blank=False)
    description = models.CharField(max_length=200, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_perspectives"


# scorecard

class scorecard(models.Model):
    # scorecard_id = models.CharField(max_length=100,null=False, blank=False)
    scorecard_description = models.CharField(
        max_length=100, null=False, blank=False, unique=True)
    functional_hierarchy_level = models.ForeignKey(
        org_functional_hierarchy, null=False, blank=False, on_delete=models.CASCADE, db_column='functional_level_id'
    )
    from_date = models.DateTimeField()
    to_date = models.DateTimeField()
    publish_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_scorecard"

# Scorecard Details


class scorecard_details(models.Model):
    scorecard_id = models.ForeignKey(
        scorecard, null=False, blank=False, on_delete=models.CASCADE, db_column='scorecard_id')
    perspective_id = models.ForeignKey(
        perspectives, null=False, blank=False, on_delete=models.CASCADE, db_column='perspective_id')
    weight = models.CharField(max_length=500, null=False, blank=False)
    weight_editable = models.BooleanField(default=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_scorecard_details"

# Bussiness goals/Objectives


class business_goals_objectives(models.Model):
    scorecard_id = models.ForeignKey(
        scorecard, null=False, blank=False, on_delete=models.CASCADE, db_column='scorecard_id')
    scorecard_details_id = models.ForeignKey(
        scorecard_details, null=False, blank=False, on_delete=models.CASCADE, db_column='scorecard_details_id')
    objective_code = models.CharField(max_length=100, null=False, blank=False)
    objective_description = models.CharField(
        max_length=500, null=True, blank=True)
    weight = models.CharField(max_length=500, null=False, blank=False)
    weight_editable = models.BooleanField(default=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        constraints = [
            # models.UniqueConstraint(fields=['scorecard_id', 'scorecard_details_id', 'objective_code'],
            #                         name='unique_scorecard_id_scorecard_details_id_objective_code')
        ]
        db_table = "tb_sc_business_goals_objectives"


# KPI Details

class kpi_details(models.Model):
    perspective_id = models.ForeignKey(
        perspectives, null=False, blank=False, db_column='perspective_id', on_delete=models.CASCADE)
    objective_id = models.ForeignKey(business_goals_objectives, null=False,
                                     blank=False, db_column='objective_id', on_delete=models.CASCADE)
    scorecard_details_id = models.ForeignKey(
        scorecard_details, null=False, blank=False, db_column='scorecard_details_id', on_delete=models.CASCADE)
    scorecard_id = models.ForeignKey(
        scorecard, null=False, blank=False, db_column='scorecard_id', on_delete=models.CASCADE)
    kpi_code = models.CharField(max_length=100, null=False, blank=False)
    kpi = models.CharField(max_length=200, null=True, blank=True)
    ytd = models.CharField(max_length=50, null=False,
                           blank=False, default="none")
    frequency = models.CharField(max_length=200, null=False, blank=False)
    period_type = models.CharField(max_length=200, null=False, blank=False)
    weight = models.CharField(max_length=200, null=False, blank=False)
    weight_editable = models.BooleanField(default=False)
    measure = models.CharField(max_length=200, null=False, blank=False)
    baseline = models.IntegerField(null=True, blank=True)
    target = models.IntegerField(null=False, blank=False)
    min = models.IntegerField(null=False, blank=False)
    max = models.IntegerField(null=False, blank=False)
    optimization = models.CharField(max_length=200, null=False, blank=False)
    chart_type = models.CharField(max_length=200, null=False, blank=False)
    actual_type = models.CharField(max_length=200, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        constraints = [
            # models.UniqueConstraint(fields=['perspective_id', 'objective_id', 'scorecard_id', 'kpi_code'],
            #                         name='unique_perspective_code_objective_code_scorecard_id_kpi_code')
        ]
        db_table = "tb_sc_kpi_details"

# Stop Light Indicators Score card KPI


class kpi_stop_light_indicators(models.Model):
    stop_light_indicator_from = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=False, blank=False)
    stop_light_indicator_to = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)], null=False, blank=False)
    stop_light_indicator = models.CharField(
        max_length=50, null=False, blank=False)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, on_delete=models.CASCADE, db_column='kpi_id')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_kpi_stop_light_indicators"

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_settings"

# KPI Actuals


class kpi_actuals(models.Model):
    scorecard_id = models.ForeignKey(
        scorecard, null=True, blank=True, db_column='scorecard_id', on_delete=models.CASCADE)
    perspective_id = models.ForeignKey(
        scorecard_details, null=True, blank=True, db_column='perspective_id', on_delete=models.CASCADE)
    objective_id = models.ForeignKey(business_goals_objectives, null=True,
                                     blank=True, db_column='objective_id', on_delete=models.CASCADE)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    period = models.DateField(null=False, blank=False)
    actuals = models.IntegerField(null=True, blank=False)
    actuals_date = models.DateField(null=True, blank=False)
    actuals_boolean = models.BooleanField(null=True, blank=False)
    summery = models.CharField(max_length=100, null=True, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        # constraints = [
        #     models.UniqueConstraint(fields=['actuals_number','actuals_date','actuals_boolean'],
        #     name='unique_perspective_code_objective_code_scorecard_id_kpi_code')
        # ]
        db_table = "tb_sc_kpi_actuals"

# KPI VIEWS


# class kpi_view(models.Model):

#     kpi = models.CharField(max_length=200)
#     baseline = models.IntegerField()
#     target = models.IntegerField()
#     min = models.IntegerField()
#     max = models.IntegerField()
#     chart_type = models.CharField(max_length=200)
#     period = models.DateField()
#     actuals = models.IntegerField()

#     class Meta:

#         managed = False
#         db_table = "kpi_view"

# KPI Dashoard VIEWS


# class kpi_dashboard_view(models.Model):

#     # id = models.IntegerField()
#     kpi = models.CharField(max_length=50)
#     min = models.IntegerField()
#     max = models.IntegerField()
#     target = models.IntegerField()
#     actuals = models.IntegerField()
#     weight = models.IntegerField()
#     performance = models.IntegerField()
#     score = models.IntegerField()
#     objective_id = models.IntegerField()
#     perspective_id = models.IntegerField()
#     scorecard_id = models.IntegerField()

#     class Meta:

#         managed = False
#         db_table = "vw_kpi_actuals_score"

# Objectives Views


# class obj_dashboard_view(models.Model):

#     # id = models.IntegerField()
#     objective_description = models.CharField(max_length=50)
#     weight = models.IntegerField()
#     score = models.IntegerField()
#     scorecard_details_id = models.IntegerField()
#     scorecard_id = models.IntegerField()

#     class Meta:

#         managed = False
#         db_table = "vw_obj_actuals_score"

# Scorecard details Perspective Views


# class sd_dashboard_view(models.Model):

#     # id = models.IntegerField()
#     description = models.CharField(max_length=50)
#     weight = models.IntegerField()
#     score = models.IntegerField()
#     perspective_id = models.IntegerField()
#     scorecard_id = models.IntegerField()

#     class Meta:

#         managed = False
#         db_table = "vw_per_actuals_score"

# ScoreCard Views


# class sc_dashboard_view(models.Model):

#     # id = models.IntegerField()
#     scorecard_description = models.CharField(max_length=50)
#     from_date = models.DateTimeField()
#     to_date = models.DateTimeField()
#     score = models.IntegerField()

#     class Meta:

#         managed = False
#         db_table = "vw_sc_actuals_score"

# class kpi_actuals_monthly_score(models.Model):

#     # id = models.IntegerField()
#     kpi = models.CharField(max_length=50)
#     min = models.IntegerField()
#     max = models.IntegerField()
#     target = models.IntegerField()
#     jan_actuals = models.IntegerField()
#     feb_actuals = models.IntegerField()
#     mar_actuals = models.IntegerField()
#     apr_actuals = models.IntegerField()
#     may_actuals = models.IntegerField()
#     jun_actuals = models.IntegerField()
#     jul_actuals = models.IntegerField()
#     aug_actuals = models.IntegerField()
#     sep_actuals = models.IntegerField()
#     oct_actuals = models.IntegerField()
#     nov_actuals = models.IntegerField()
#     dec_actuals = models.IntegerField()
#     jan_performance = models.IntegerField()
#     jan_score = models.IntegerField()
#     feb_performance = models.IntegerField()
#     feb_score = models.IntegerField()
#     mar_performance = models.IntegerField()
#     mar_score = models.IntegerField()
#     apr_performance = models.IntegerField()
#     apr_score = models.IntegerField()
#     may_performance = models.IntegerField()
#     may_score = models.IntegerField()
#     jun_performance = models.IntegerField()
#     jun_score = models.IntegerField()
#     jul_performance = models.IntegerField()
#     jul_score = models.IntegerField()
#     aug_performance = models.IntegerField()
#     aug_score = models.IntegerField()
#     sep_performance = models.IntegerField()
#     sep_score = models.IntegerField()
#     oct_performance = models.IntegerField()
#     oct_score = models.IntegerField()
#     nov_performance = models.IntegerField()
#     nov_score = models.IntegerField()
#     dec_performance = models.IntegerField()
#     dec_score = models.IntegerField()
#     weight = models.IntegerField()
#     objective_description = models.CharField(max_length=50)
#     scorecard_description = models.CharField(max_length=50)
#     perspective_description = models.CharField(max_length=50)
#     objective_id = models.IntegerField()
#     perspective_id = models.IntegerField()
#     scorecard_id = models.IntegerField()

#     class Meta:

#         managed = False
#         db_table = "vw_kpi_actuals_monthly_score"


class kpi_actuals_monthly_score(models.Model):

    # id = models.IntegerField()
    kpi = models.CharField(max_length=50)
    min = models.IntegerField()
    max = models.IntegerField()
    target = models.IntegerField()
    actuals = models.IntegerField()
    actual_month = models.CharField(max_length=50)
    performance = models.IntegerField()
    score = models.IntegerField()
    weight = models.DecimalField(max_digits=10, decimal_places=2)
    objective_description = models.CharField(max_length=100)
    objective_code = models.CharField(max_length=50)
    scorecard_description = models.CharField(max_length=100)
    perspective_description = models.CharField(max_length=100)
    objective_id = models.IntegerField()
    perspective_id = models.IntegerField()
    scorecard_id = models.IntegerField()

    class Meta:

        managed = False
        db_table = "vw_kpi_actuals_monthly_score"

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_chart_attributes_options"


class kpi_pending_actions(models.Model):
    user_id = models.IntegerField(null=False, blank=False)
    kpi = models.CharField(max_length=500, null=False, blank=False)
    message = models.CharField(max_length=500, null=False, blank=False)
    upcoming_date = models.DateTimeField(
        max_length=500, null=True, blank=True)
    kpi_id = models.IntegerField(null=False, blank=False, default='0')
    action = models.CharField(max_length=20, null=False, blank=False)
    show_flag = models.CharField(
        max_length=1, null=False, blank=False, default='Y')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_kpi_pending_actions"


# Kpi User Access

class kpi_user_access(models.Model):
    user_id = models.IntegerField(null=False, blank=False)
    # kpi_id = models.IntegerField(null=False, blank=False)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    kpi_owner = models.CharField(
        max_length=1, null=False, blank=False, default='N')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_kpi_user_access"


# Kpi stop light indicator

class kpi_sli(models.Model):
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    sli_from = models.IntegerField(null=False, blank=False)
    sli_to = models.IntegerField(null=False, blank=False)
    sli = models.CharField(max_length=10, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_kpi_sli"

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_smtp_configure"

# ! test model

# class test_model(models.Model):
#     feild1=models.CharField(max_length=100, null=False, blank=False)
#     feild2=models.CharField(max_length=100,null=False, blank=False)
#     feild3=models.CharField(max_length=100,null=False, blank=False)

#     class Meta:
#         db_table="test_table"

# ! test model end

# Kpi score Initiative


class initiative(models.Model):
    scorecard_description = models.CharField(max_length=500)
    scorecard_id = models.ForeignKey(
        scorecard, null=False, blank=False, db_column='scorecard_id', on_delete=models.CASCADE)
    perspective_id = models.ForeignKey(
        scorecard_details, null=False, blank=False, db_column='perspective_id', on_delete=models.CASCADE)
    objective_id = models.ForeignKey(business_goals_objectives, null=False,
                                     blank=False, db_column='objective_id', on_delete=models.CASCADE)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    action_item = models.CharField(max_length=500, null=False, blank=False)
    target_date = models.DateTimeField(null=False, blank=False)
    ownership = models.CharField(max_length=100, null=False, blank=False)
    status = models.CharField(max_length=20, null=False, blank=False)
    comments = models.CharField(max_length=500, null=True, blank=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_initiative"

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


# KPI pin to dashboard

class kpi_pin_dashboard(models.Model):
    id = models.AutoField(primary_key=True)
    kpi_name = models.CharField(max_length=300, null=False, blank=False)
    kpi_score = models.IntegerField(null=False, blank=False)
    pin_flag = models.CharField(max_length=1, null=False, default='Y')
    user_id = models.IntegerField(null=False, blank=False)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tb_sc_kpi_pin_dashboard"

# kpi pin dashboard view


# class vw_kpi_pin_dashboard(models.Model):

#     # id = models.IntegerField()
#     kpi_name = models.CharField(max_length=300)
#     kpi_score = models.IntegerField()
#     # min = models.IntegerField()
#     # max = models.IntegerField()
#     target = models.IntegerField()
#     curr_actuals = models.IntegerField()
#     prev_actuals = models.IntegerField()
#     # weight = models.IntegerField()
#     curr_performance = models.IntegerField()
#     prev_performance = models.IntegerField()
#     curr_score = models.IntegerField()
#     prev_score = models.IntegerField()
#     objective_id = models.IntegerField()
#     perspective_id = models.IntegerField()
#     scorecard_id = models.IntegerField()
#     kpi_id = models.IntegerField()
#     user_id = models.IntegerField()
#     pin_flag = models.CharField(max_length=300)

#     class Meta:
#         managed = False
#         db_table = "vw_kpi_pin_dashboard"

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


class user_license(models.Model):
    license_key = models.CharField(max_length=50, null=False, blank=False)
    user_id = models.IntegerField(null=True, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_user_license"


class pin_chart_to_homepage(models.Model):
    id = models.AutoField(primary_key=True)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    chart_type = models.CharField(max_length=200, null=False, blank=False)
    order_no = models.IntegerField(default=0)
    user_id = models.IntegerField(null=False, blank=False)
    pin_flag = models.CharField(
        max_length=1, null=False, blank=False, default='Y')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tb_sc_pin_chart_to_homepage"


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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

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
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_sso_configure"


class notification(models.Model):
    id = models.AutoField(primary_key=True)
    message = models.CharField(max_length=255, null=False, blank=False)
    action = models.CharField(max_length=20, null=False, blank=False)
    permission = models.ForeignKey(
        Group, null=False, blank=False, db_column='permission', on_delete=models.CASCADE)
    show_flag = models.IntegerField(null=False, blank=False)
    notification_type = models.CharField(
        max_length=20, null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tb_sc_notification"



# Query Builder Connection Definition Table

class rb_db_connect_table(models.Model):
    id = models.AutoField(primary_key=True)
    connection_name = models.CharField(max_length=255,null=False,blank=False)
    database_name = models.CharField(max_length=255,null=False,blank=False)
    database_type = models.CharField(max_length=255, null=False, blank=False)
    user_name = models.CharField(max_length=50, null=False, blank=False)
    password = models.CharField(max_length=50, null=True, blank=True)
    host_id = models.CharField(max_length=20,null=False, blank=False)
    port = models.IntegerField(null=False, blank=False)
    service_name_or_SID = models.CharField(max_length=20,null=True, blank=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "rb_tb_sc_db_connect_table"


# Query Builder Definition
class query_definition(models.Model):
    id = models.AutoField(primary_key=True)
    query_name = models.CharField(max_length=255, null=False, blank=False)
    connection_id = models.ForeignKey(rb_db_connect_table,null=False,blank=False,db_column="connection_id",on_delete=models.CASCADE)
    query_text = models.TextField(null=False, blank=False)
    created_user = models.CharField(max_length=255, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')
    query_status = models.BooleanField(default=False)
    query_type = models.BooleanField(default=False)

    class Meta:
        db_table = "tb_sqb_query_definition"
    

# Shared Query Definition
class shared_query_definition(models.Model):
    id = models.AutoField(primary_key=True)
    permission_to = models.CharField(max_length=255, null=False, blank=False)
    permission_by = models.CharField(max_length=255, null=False, blank=False)
    permission_type = models.CharField(max_length=255, null=False, blank=False)
    query_id = models.IntegerField(null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')
    
    class Meta:
        db_table = "tb_sqb_shared_query_definition"

# Query Builder Table

class query_builder_table(models.Model):
    id = models.AutoField(primary_key=True)
    table_name = models.CharField(max_length=255, null=False, blank=False)
    table_id = models.CharField(max_length = 255, null=False,blank= False)
    query_id = models.ForeignKey(query_definition, null=False, blank=False, db_column='query_id', on_delete=models.CASCADE)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sqb_query_builder_table"

# Query Builder Cols

class query_builder_table_columns(models.Model):
    id = models.AutoField(primary_key=True)
    column_name = models.CharField(max_length=255,null=True, blank=False)
    alias_name = models.CharField(max_length=255, null=True, blank=False)
    sort_type = models.CharField(max_length=255, null=True, blank=True)
    sort_order = models.IntegerField(null=True, blank=True)
    sort_column = models.CharField(max_length=255, null=True, blank=True)
    group_by = models.CharField(max_length=255, null=True, blank=True)
    col_function = models.CharField(max_length=255, null=True, blank=True)
    column_display_order = models.IntegerField(null=True, blank=True)
    column_display_ind = models.CharField(max_length=255, null=True, blank=True)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')
    table_column_table_id = models.ForeignKey(query_builder_table, null=False, blank=False, db_column='table_column_table_id', on_delete=models.CASCADE)
    table_column_query_id = models.ForeignKey(query_definition, null=False, blank=False, db_column='table_column_query_id', on_delete=models.CASCADE)

    class Meta:
        db_table = "tb_sqb_query_builder_table_columns"

# Query Builder Joins

class query_builder_table_joins(models.Model):
    id = models.AutoField(primary_key=True)
    tab_join_table_id_one = models.ForeignKey(
        query_builder_table,
        related_name='tab_join_table_one',
        null=False, blank=False,
        db_column='tab_join_table_id_one',
        on_delete=models.CASCADE
    )
    tab_join_table_id_two = models.ForeignKey(
        query_builder_table,
        related_name='tab_join_table_id_two',
        null=False, blank=False,
        db_column='tab_join_table_id_two',
        on_delete=models.CASCADE
    )
    tab_join_query_id = models.ForeignKey(
        query_definition,
        null=False, blank=False,
        db_column='tab_join_query_id',
        on_delete=models.CASCADE
    )
    join_type = models.CharField(max_length=255, null=True, blank=False)
    join_column_name1 = models.CharField(
        max_length=255, null=True, blank=False)
    join_column_name2 = models.CharField(
        max_length=255, null=True, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sqb_query_builder_table_joins"

# Query Builder Alias

class query_builder_table_alias(models.Model):
    id = models.AutoField(primary_key=True)
    col_alias_table_id = models.ForeignKey(
        query_builder_table, null=False, blank=False, db_column='col_alias_table_id', on_delete=models.CASCADE)
    col_alias_query_id = models.ForeignKey(
        query_definition, null=False, blank=False, db_column='col_alias_query_id', on_delete=models.CASCADE)
    col_alias_column_id = models.ForeignKey(
        query_builder_table_columns, null=False, blank=False, db_column='col_alias_column_id', on_delete=models.CASCADE)
    alias_name = models.CharField(max_length=255, null=False, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sqb_query_builder_table_alias"

# Query Builder Filter

class query_builder_table_column_filter(models.Model):
    id = models.AutoField(primary_key=True)
    column_name = models.CharField(max_length=255, null=False, blank=False)
    column_filter = models.CharField(max_length=255, null=False, blank=False)
    column_value = models.CharField(max_length=255, null=False, blank=False)
    tab_filter_tale_id = models.ForeignKey(
        query_builder_table, null=False, blank=False, db_column='tab_filter_tale_id', on_delete=models.CASCADE)
    tab_filter_query_id = models.ForeignKey(
        query_definition, null=False, blank=False, db_column='tab_filter_query_id', on_delete=models.CASCADE)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(
        max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sqb_query_builder_table_column_filter"

# Query Builder GroupBy

class query_builder_table_groupBy(models.Model):
    id = models.AutoField(primary_key=True)
    table_grp_table_id = models.ForeignKey(query_builder_table, null=False, blank=False, db_column='table_grp_table_id', on_delete=models.CASCADE)
    table_grp_query_id = models.ForeignKey(query_definition, null=False, blank=False, db_column='table_grp_query_id', on_delete=models.CASCADE)
    table_grp_column_id = models.ForeignKey(query_builder_table_columns,null=False,blank=False,db_column='table_grp_column_id',on_delete=models.CASCADE)
    groupbyFunction = models.CharField(max_length=255, null=True, blank=False)
    having_filter_ind = models.CharField(max_length=1, null=True, blank=False)
    having_filter_operator = models.CharField(max_length=255, null=True, blank=False)
    having_filter_value = models.IntegerField(null=True, blank=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sqb_query_builder_table_groupBy"


class query_builder_aggeration_function_table(models.Model):
    id = models.AutoField(primary_key=True)
    agg_fun_name = models.CharField(max_length=255,null=True, blank=False)
    
    table_aggragate_query_id = models.ForeignKey(query_definition, null=False, blank=False, db_column='table_aggragate_query_id', on_delete=models.CASCADE)
    
    table_aggregate_table_id = models.ForeignKey(query_builder_table, null=False, blank=False, db_column='table_aggregate_table_id', on_delete=models.CASCADE)
    
    table_aggregate_column_id = models.ForeignKey(query_builder_table_columns,null=False,blank=False,db_column='table_aggregate_column_id',on_delete=models.CASCADE)    
        
    
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')
    
    class Meta:
        db_table = "tb_sqb_query_builder_aggreation_table"
    

# Organization modesl logo path


def profile_pic_upload_path(instance, filename):
    obj = user_profile.objects.all().last()
    ext = filename.split('.')
    if obj == None:
        file_name = "user_profile_%s.%s" % (1, ext[1])
    elif instance.id == None:
        file_name = "user_profile_%s.%s" % (obj.id+1, ext[1])
    else:
        file_name = "user_profile_%s_upd.%s" % (instance.id, ext[1])
    # print(file_name)
    return file_name
    # '/'.join([file_name])

# Model for Individiual User Profile
class user_profile(models.Model):
    user_id = models.ForeignKey(
        User, null=False, blank=False, db_column='user_id', on_delete=models.CASCADE)
    profile_pic = models.ImageField(null=True, blank=True, upload_to=profile_pic_upload_path)
    username = models.CharField(max_length=100, null=False, blank=False)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    email = models.CharField(max_length=100, null=False, blank=False)
    temporary_address = models.CharField(max_length=100, null=True, blank=True)
    permanent_address = models.CharField(max_length=100, null=True, blank=True)
    contact = models.CharField(max_length=10,null=True, blank=True)
    user_group = models.CharField(max_length=100, null=False, blank=False)
    user_status = models.BooleanField(default=False)
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_user_profile"


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
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_countries"

class states(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, null=True, blank=True)
    iso2 = models.CharField(max_length=10, null=True, blank=True)
    country_id = models.ForeignKey(
        countries, null=False, blank=False, db_column='country_id', on_delete=models.CASCADE)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_states"


# Model for Computation Logic
class computation_details(models.Model):
    id = models.AutoField(primary_key=True)
    kpi_id = models.ForeignKey(
        kpi_details, null=False, blank=False, db_column='kpi_id', on_delete=models.CASCADE)
    period_column = models.CharField(max_length=500, null=True, blank=True)
    value_type = models.CharField(max_length=100, null=True, blank=True)
    drill_down_value = models.CharField(max_length=100, null=True, blank=True)
    no_of_sheets = models.IntegerField(null=True, blank=True)
    sheet1 = models.CharField(max_length=100, null=True, blank=True)
    sheet2 = models.CharField(max_length=100, null=True, blank=True)
    computation_logic = models.CharField(max_length=500, null=False, blank=False)
    filter_condition = models.CharField(max_length=500, null=True, blank=True)
    url = models.CharField(max_length=1000, null=True, blank= True)
    user_name = models.CharField(max_length=500, blank=True, null=True)
    Password = models.CharField(max_length=500, blank=True, null=True)
    Computation_type = models.CharField(max_length=1, null=False, blank=False, default='N')
    created_by = models.IntegerField(null=False, blank=False)
    created_date = models.DateTimeField(auto_now_add=True)
    last_updated_by = models.IntegerField(null=False, blank=False)
    last_updated_date = models.DateTimeField(auto_now=True)
    delete_flag = models.CharField(max_length=1, null=False, blank=False, default='N')

    class Meta:
        db_table = "tb_sc_computation_details"