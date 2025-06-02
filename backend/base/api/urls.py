from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path("", views.getRoutes),
    path("token/", views.MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    
    path("ssotoken/", views.MySSOTokenObtainPairView.as_view(), name="ssotoken_obtain_pair"),
    
    
    path(
        "update_profile/<int:pk>/",
        views.UpdateActiveView.as_view(),
        name="auth_update_profile",
    ),
    path("createuser", views.save_users),
    path("upd_user_column/<int:id>", views.upd_user_column),

    
    # For SSO Users insert at auth_group
    path("createmsuser", views.ms_save_users),
    path("get_auth_group", views.get_auth_group),
    path("get_user_groups", views.get_user_groups),
    path("get_user_groups/<int:id>/", views.get_user_groups),
    path("get_range_user_groups/<int:start>/<int:end>/", views.get_range_user_groups),
    path("ins_user_groups", views.ins_user_groups),
    path("ins_user_groups", views.ins_user_groups),
        
    # For SSO Users insert at user_group
    path("ms_ins_user_groups", views.ms_ins_user_groups),
    path("upd_user_groups", views.upd_user_groups),
    
    # license
    path("get_license", views.get_license),
    path("ins_upd_license/<int:id>/", views.ins_upd_license),
    
    #  smtp
    path("get_smtp", views.get_smtp),
    path("ins_upt_smtp", views.ins_upt_smtp),
    
    #  Forgot Password
    path("forgot_password", views.forgot_password),
    
    # Session
    path("updatesession/<int:uid>/", views.updatesession),
    path("updatesession/<int:uid>/<str:update>/", views.updatesession),
    path("deletesession/<int:uid>/", views.deletesession),
    
    # session Configuration
    path("getsessionconfig", views.get_session_configuration),
    path("ins_upd_session_config/<int:id>/", views.ins_upd_session_configuration),
    # path("deletesession/<int:uid>/", views.deletesession),
    
    # SSO
    path("ins_sso", views.ins_sso),
    path("get_sso", views.get_sso),
    path("upd_sso/<int:id>/", views.upd_sso),
    
    # User Profile URLS
    path("ins_user_profile", views.ins_user_profile),
    path("get_user_profile", views.get_user_profile),
    path("get_user_profile/<int:id>/", views.get_user_profile),
    path("upd_user_profile/<int:id>/", views.upd_user_profile),
    path("del_user_profile/<int:id>/", views.del_user_profile),
    
    # Organization definition level URLS
    path("ins_org_definition", views.ins_org_definition),
    path("get_org_definition", views.get_org_definition),
    path("get_org_definition/<int:id>/", views.get_org_definition),
    path("upd_org_definition/<int:id>/", views.upd_org_definition),
    path("del_org_definition/<int:id>/", views.del_org_definition),
    
    # Stop Light Indicators level URLS
    path(
        "get_org_definition_stop_light_indicators",
        views.get_org_definition_stop_light_indicators,
    ),
    path(
        "ins_org_definition_stop_light_indicators",
        views.ins_org_definition_stop_light_indicators,
    ),
    path(
        "upd_org_definition_stop_light_indicators/<int:id>/",
        views.upd_org_definition_stop_light_indicators,
    ),
    path(
        "del_org_definition_stop_light_indicators/<int:id>/",
        views.del_org_definition_stop_light_indicators,
    ),
    
    # Organization fuctional level URLS
    path("ins_org_functional_level", views.ins_org_functional_level),
    path("get_org_functional_level", views.get_org_functional_level),
    path(
        "get_range_org_functional_level/<int:start>/<int:end>/",
        views.get_range_org_functional_level,
    ),
    path(
        "get_range_org_functional_level/<int:start>/<int:end>/<str:search>/",
        views.get_range_org_functional_level,
    ),
    path("upd_org_functional_level/<int:id>/", views.upd_org_functional_level),
    path("del_org_functional_level/<int:id>/", views.del_org_functional_level),
    
    # org Functiona herarchy
    path("ins_org_functional_hierarchy", views.ins_org_functional_hierarchy),
    path("get_org_functional_hierarchy/<int:id>/", views.get_org_functional_hierarchy),
    path("get_org_functional_hierarchy", views.get_org_functional_hierarchy),
    path("upd_org_functional_hierarchy/<int:id>/", views.upd_org_functional_hierarchy),
    path("del_org_functional_hierarchy/<int:id>/", views.del_org_functional_hierarchy),
    # TEST URL PATH
    path(
        "del_org_functional_hierarchy_2/<int:id_1>/<int:id_2>/<int:id_3>/",
        views.del_org_functional_hierarchy_2,
    ),
    path("get_org_functional_hierarchy_2/", views.get_org_functional_hierarchy_2),
    path(
        "del_org_functional_hierarchy_3/<int:id_1>/",
        views.del_org_functional_hierarchy_3,
    ),
    # navigation_menu_details
    path("get_navigation_menu_details", views.get_navigation_menu_details),
    path("get_navigation_menu_details/<int:id>/", views.get_navigation_menu_details),
    path("get_single_navigation_menu_details/<int:id>/", views.get_single_navigation_menu_details),
    path("ins_navigation_menu_details", views.ins_navigation_menu_details),
    # user_access_definition
    path("ins_user_access", views.ins_user_access),
    path("get_user_access_definition", views.get_user_access_definition),
    path("get_user_access_definition/<int:id>/", views.get_user_access_definition),
    
    # join group and group_access_definition
    path("join_user_group_access", views.group_group_access),
    path("join_user_group_access/<int:id>/", views.group_group_access),
    path("join_user_group_access/<int:id>/<int:menu_id>/", views.group_group_access),
    
    # path("get_menu_access", view=views.get_menu_access_view),
    # group_access_definition
    path("ins_group_access", views.ins_group_access),
    path("get_group_access_definition", views.get_group_access_definition),
    path("get_group_access_definition/<int:id>/", views.get_group_access_definition),
    #     path('get_menu_access', view=views.get_menu_access_view),
    path("upd_group_access_definition", views.upd_group_access_definition),
    path("upd_group_access_definition/<int:id>/", views.upd_group_access_definition),
    
    path("get_chart_attributes/", views.get_chart_attributes),
    path("get_chart_attributes/<int:id>/", views.get_chart_attributes),
    path("get_chart_attributes/<int:id>/<str:chart_type>/", views.get_chart_attributes),
    path("get_chart_attributes/<str:chart_type>/", views.get_chart_attributes),
    # Chart Attributes Settings URL
    path("get_chart_attributes_settings/", views.get_chart_attributes_settings),
    path(
        "get_chart_attributes_settings/<int:id>/", views.get_chart_attributes_settings
    ),
    path(
        "get_chart_attributes_settings/<int:id>/<str:chart_type>/",
        views.get_chart_attributes_settings,
    ),
    path(
        "get_chart_attributes_settings/<str:chart_type>/",
        views.get_chart_attributes_settings,
    ),
    path(
        "get_chart_attributes_settings/<int:id>/<str:chart_type>/<str:component>/",
        views.get_chart_attributes_settings,
    ),
    path(
        "get_chart_attributes_settings/<str:chart_type>/<str:component>/",
        views.get_chart_attributes_settings,
    ),
    path(
        "get_chart_attributes_settings/<int:id>/<str:chart_type>/<str:component>/<str:attr_name>/",
        views.get_chart_attributes_settings,
    ),
    path(
        "get_chart_attributes_settings/<str:chart_type>/<str:component>/<str:attr_name>/",
        views.get_chart_attributes_settings,
    ),
    path("upd_chart_attributes_settings", views.upd_chart_attributes_settings),
    path(
        "upd_chart_attributes_settings/<int:id>/", views.upd_chart_attributes_settings
    ),
    # Chart Attributes Options
    path("get_chart_attributes_options", views.get_chart_attributes_options),
    
    # Config Codes URLS
    path("ins_config_codes", views.ins_config_codes),
    path("get_config_codes", views.get_config_codes),
    path("get_config_codes/<str:value>/", views.get_config_codes),
    path("get_config_details/<str:search>/", views.get_config_details),
    path("get_range_config_codes/<int:start>/<int:end>/", views.get_range_config_codes),
    path("get_range_config_codes/<int:start>/<int:end>/<str:search>/", views.get_range_config_codes),
    path("upd_config_codes/<int:id>/", views.upd_config_codes),
    path("del_config_codes/<int:id>/", views.del_config_codes),
    # settings
    path("get_settings", views.get_settings),
    path("get_settings/<int:id>/", views.get_settings),
    path("upd_settings", views.upd_settings),
    path("upd_settings/<int:id>/", views.upd_settings),
    # Global helper
    path("get_helper/<int:id>/", views.get_helper),
    path("get_helper", views.get_helper),
    # Global Error Message
    path("get_warnings", views.get_warnings),
    path("get_countries",views.get_countries),
    path("get_state/<int:id>/",views.get_state),
    path("get_state",views.get_state),
    # get auth user details
    path("get_user_details", views.get_user_details),
    path("get_user_details_with_profile", views.get_user_details_with_profile),
    path("get_range_user_details_with_profile/<int:start>/<int:end>/", views.get_range_user_details_with_profile),
    path("get_range_user_details_with_profile/<int:start>/<int:end>/<str:search>/", views.get_range_user_details_with_profile),
    path("get_Prticular_user_details/<int:id>/", views.get_Prticular_user_details),
    path("get_logged_in_user/<int:id>/", views.get_logged_in_user),
    # Compliance details URLS
    path("ins_compliance_details", views.ins_compliance_details),
    path("ins_compliance_details_bulk", views.ins_compliance_details_bulk),
    path("get_range_compliance_details/<int:start>/<int:end>/", views.get_range_compliance_details),
    path("get_range_compliance_details/<int:start>/<int:end>/<str:search>/", views.get_range_compliance_details),
    path("upd_compliance_details/<int:id>/", views.upd_compliance_details),
    path("del_compliance_details/<int:id>/", views.del_compliance_details),
    # CounterParty Details and Compliance Actuals URLS
    path("ins_counterparty_compliance_actuals", views.ins_counterparty_compliance_actuals),
    path("upd_counterparty_compliance_actuals/<int:id>/", views.upd_counterparty_compliance_actuals),
    path("upd_compliance_actuals", views.upd_compliance_actuals),
    
    path("get_range_counterparty_details/<int:start>/<int:end>/", views.get_range_counterparty_details),
    # path("get_range_counterparty_details/<int:start>/<int:end>/<str:search>/", views.get_range_counterparty_details),
    path("get_range_counterparty_details/<int:start>/<int:end>/<str:region>/", views.get_range_counterparty_details),
    path("del_counterparty_details/<int:id>/", views.del_counterparty_details),
    # Compliance Actuals URLS
    path("get_range_compliance_actuals/<int:start>/<int:end>/", views.get_range_compliance_actuals),
    path("get_range_compliance_actuals/<int:start>/<int:end>/<str:search>/", views.get_range_compliance_actuals),
    path("del_compliance_actuals/<int:id>/", views.del_compliance_actuals),
    # GET
    path("get_compliance_details/<int:id>/", views.get_compliance_details),
    path("get_compliance_details", views.get_compliance_details),
    path("get_counterparty_details/<int:id>/", views.get_counterparty_details),
    path("get_counterparty_details", views.get_counterparty_details),
    path("get_compliance_actuals/<int:id>/", views.get_compliance_actuals),
    path("get_compliance_actuals", views.get_compliance_actuals),

    # compliance Codes URLS
    path("ins_compliance_codes", views.ins_compliance_codes),
    path("get_compliance_codes", views.get_compliance_codes),
    path("get_range_compliance_codes/<int:start>/<int:end>/", views.get_range_compliance_codes),
    path("get_range_compliance_codes/<int:start>/<int:end>/<str:search>/", views.get_range_compliance_codes),
    path("upd_compliance_codes/<int:id>/", views.upd_compliance_codes),
    path("del_compliance_codes/<int:id>/", views.del_compliance_codes),
    path("get_compliance_dashboard", views.get_compliance_dashboard),
    path("get_compliance_dashboard/<str:region>/", views.get_compliance_dashboard),
    path("get_compliance_summary", views.get_compliance_summary),
    # path("get_default_json_structure", views.get_default_json_structure),
    path("getempregdetails", views.getEmpRegDetails),
    path("ins_upd_counterparty_profile", views.ins_upd_counterparty_profile),
    path("ins_upd_counterparty_profile/<int:id>/", views.ins_upd_counterparty_profile),
    path("get_counterparty_profile", views.get_counterparty_profile),
    path("get_counterparty_profile/<int:id>/", views.get_counterparty_profile),
    path("get_range_counterparty_profile/<int:start>/<int:end>/", views.get_range_counterparty_profile),
    path("get_range_counterparty_profile/<int:start>/<int:end>/<str:search>/", views.get_range_counterparty_profile),
    path("del_counterparty_profile/<int:id>/", views.del_counterparty_profile),
    
    # Plant details API URL
    path("ins_upd_plant_details", views.ins_upd_plant_details),
    path("ins_upd_plant_details/<int:id>/", views.ins_upd_plant_details),
    path("get_plant_details", views.get_plant_details),
    path("get_plant_details/<int:id>/", views.get_plant_details),
    path("get_range_plant_details/<int:start>/<int:end>/", views.get_range_plant_details),
    path("get_range_plant_details/<int:start>/<int:end>/<str:search>/", views.get_range_plant_details),
    path("del_plant_details/<int:id>/", views.del_plant_details),
    
    path(
        "change_password/<int:pk>/",
        views.ChangePasswordView.as_view(),
        name="auth_change_password",
    ),

    path(
        "change_password_admin/<int:pk>/",
        views.ChangePasswordForAdminView.as_view(),
        name="auth_change_password",
    ),

    path("FilePost", views.FilePost),
    path("Fileget/<int:id>/", views.Fileget),
    path("FileNameget/<int:id>/", views.get_file_names),
    
    # Compliance Initiative
    path("get_sc_initiative/<int:id>/<int:compid>/", views.get_sc_initiative),
    path("ins_sc_initiative", views.ins_sc_initiative),
    path("get_sc_initiative_details", views.get_sc_initiative_details),
    path("sso_create_and_initialize_user", views.sso_create_and_initialize_user),    
    path("get_user_activity", views.get_user_activity),
    
    path("get_kpi_dashboard_view/<int:id>/", views.get_kpi_dashboard_view),
    
    # Compliance Indicators URLS
    path("get_compliance_indicators",views.get_compliance_indicators),
    path("ins_compliance_indicators",views.ins_compliance_indicators),
    path("upd_compliance_indicators/<int:id>/",views.upd_compliance_indicators),
    path("del_compliance_indicators/<int:id>/",views.del_compliance_indicators),
    
    # Compliance Summary API
    path("get_compliance_summary",views.get_compliance_summary),
    path("get_compliance_summary/<str:region>/",views.get_compliance_summary),
        
    # Compliance Summary API V2
    path("get_compliance_summary_v2",views.get_compliance_summary_v2),
    path("get_compliance_summary_v2/<str:region>/",views.get_compliance_summary_v2),
    path("get_compliance_summary_v2/<str:region>/<int:year>/",views.get_compliance_summary_v2),
    path("get_compliance_summary_v2/<str:region>/<int:year>/<int:plant>/",views.get_compliance_summary_v2),
    
]