from django.urls import URLPattern, path
from . import rb_views
from . import views
from . import updater
from .views import (
    search_currency_code,
    search_currency_name,
    search_perspective,
    search_config_type,
    search_scorecard_description,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.views.static import serve

# from .date_for_url import DateConverter
from django.urls import path, register_converter

# For date as a datatype to pass in url
# register_converter(DateConverter, 'date')


urlpatterns = [
    path("", views.getRoutes),
    path("token/", views.MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path(
        "change_password/<int:pk>/",
        views.ChangePasswordView.as_view(),
        name="auth_change_password",
    ),
    path("getempregdetails", views.getEmpRegDetails),
    path("checkadmin/<str:username>/", views.checkadmin),
    path(
        "update_profile/<int:pk>/",
        views.UpdateActiveView.as_view(),
        name="auth_update_profile",
    ),
    path("createuser", views.save_users),
    # For SSO Users insert at auth_group
    path("createmsuser", views.ms_save_users),
    path("get_auth_group", views.get_auth_group),
    path("get_user_groups", views.get_user_groups),
    path("get_range_user_groups/<int:start>/<int:end>/", views.get_range_user_groups),
    path("get_user_groups/<int:id>/", views.get_user_groups),
    path("ins_user_groups", views.ins_user_groups),
    # For SSO Users insert at user_group
    path("ms_ins_user_groups", views.ms_ins_user_groups),
    path("upd_user_groups", views.upd_user_groups),
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
    # Stop Light Indicators level URLS Scorecard KPI
    path("ins_kpi_stop_light_indicators", views.ins_kpi_stop_light_indicators),
    path("get_kpi_stop_light_indicators", views.get_kpi_stop_light_indicators),
    path(
        "get_kpi_stop_light_indicators_id/<int:kpi_id>/",
        views.get_kpi_stop_light_indicators_id,
    ),
    # path('get_stop_light_indicators/<int:id>/', views.get_stop_light_indicators),
    path(
        "upd_kpi_stop_light_indicators/<int:id>/", views.upd_kpi_stop_light_indicators
    ),
    path(
        "del_kpi_stop_light_indicators/<int:id>/", views.del_kpi_stop_light_indicators
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
    # Currencies URLS
    path("ins_currencies", views.ins_currencies),
    path("upd_currencies/<int:id>/", views.upd_currencies),
    path("del_currencies/<int:id>/", views.del_currencies),
    path("get_range_currencies/<int:start>/<int:end>/<str:search>/", views.get_range_currencies),
    path("get_range_currencies/<int:start>/<int:end>/", views.get_range_currencies),
    path("get_currencies", views.get_currencies),
    path(
        "get_range_currenciesmodal/<int:start>/<int:end>/",
        views.get_range_currenciesmodal,
    ),
    # partialsearch for currencycode urls.py
    path("currency_code/", search_currency_code.as_view()),
    path("currency_name/", search_currency_name.as_view()),
    path(
        "currency_dual/<str:currency_code>/<str:currency_name>/",
        views.search_currency_dual,
    ),
    # multivalue(,)seperatedfilter for currency_code,currency_name start
    path("multivaluesccode/<str:currency_code>/", views.multifilterccode),
    path("multivaluescname/<str:currency_name>/", views.multifiltercname),
    # end
    # Modal_Component testing urls in perspective report start
    path("perspective/", search_perspective.as_view()),
    path("get_range_perspective/<int:start>/<int:end>/", views.get_range_perspective),
    path(
        "multivaluesperspective/<str:perspective>/", views.multifilterccodeperspective
    ),
    path("config_type/", search_config_type.as_view()),
    path("multivaluesconfig/<str:config_type>/", views.multifilterconfigtype),
    # end
    # Organizatin Settings
    path("get_org_settings", views.get_org_settings),
    path("ins_org_settings", views.ins_org_settings),
    path("upd_org_settings/<int:id>/", views.upd_org_settings),
    path("del_org_settings/<int:id>/", views.del_org_settings),
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
    path("get_menu_access", view=views.get_menu_access_view),
    # group_access_definition
    path("ins_group_access", views.ins_group_access),
    path("get_group_access_definition", views.get_group_access_definition),
    path("get_group_access_definition/<int:id>/", views.get_group_access_definition),
    #     path('get_menu_access', view=views.get_menu_access_view),
    path("upd_group_access_definition", views.upd_group_access_definition),
    path("upd_group_access_definition/<int:id>/", views.upd_group_access_definition),
    # uom
    path("ins_uom", views.ins_uom),
    path("get_uom", views.get_uom),
    path("get_range_uom/<int:start>/<int:end>/", views.get_range_uom),
    path("upd_uom/<int:id>/", views.upd_uom),
    path("del_uom/<int:id>/", views.del_uom),
    # Config Codes URLS
    path("ins_config_codes", views.ins_config_codes),
    path("get_config_codes", views.get_config_codes),
    path("get_range_config_codes/<int:start>/<int:end>/", views.get_range_config_codes),
    path("get_range_config_codes/<int:start>/<int:end>/<str:search>/", views.get_range_config_codes),
    path("upd_config_codes/<int:id>/", views.upd_config_codes),
    path("del_config_codes/<int:id>/", views.del_config_codes),
    # path('ins_user_access_definition',views.ins_user_access_definition),
    # path('get_user_access_definition',views.get_user_access_definition),
    path("upd_user_access_definition", views.upd_user_access_definition),
    path("upd_user_access_definition/<int:id>/", views.upd_user_access_definition),
    # path('all_user_access_definition',UserAccessViews.as_view()),
    # get auth user details
    path("get_user_details", views.get_user_details),
    path("get_Prticular_user_details/<int:id>/", views.get_Prticular_user_details),

    # join user and user_access_definition
    path("join_user_user_access/<int:id>/", views.user_user_access),
    path("join_user_user_access/<int:id>/<int:menu_id>/", views.user_user_access),
    # join group and group_access_definition
    path("join_user_group_access", views.group_group_access),
    path("join_user_group_access/<int:id>/", views.group_group_access),
    path("join_user_group_access/<int:id>/<int:menu_id>/", views.group_group_access),
    path("get_menu_access", view=views.get_menu_access_view),
    # Perspectives URLS
    path("ins_perspectives", views.ins_perspectives),
    path("get_perspectives", views.get_perspectives),
    path("get_perspectives/<int:to>/", views.get_perspectives),
    path("get_range_perspectives/<int:start>/<int:end>/", views.get_range_perspectives),
    path("get_range_perspectives/<int:start>/<int:end>/<str:search>/", views.get_range_perspectives),

    path("upd_perspectives/<int:id>/", views.upd_perspectives),
    path("del_perspectives/<int:id>/", views.del_perspectives),
    # Bussiness goals/Objectives
    path("ins_bussniess_goal_objective", views.ins_bussniess_goal_objective),
    path("get_bussniess_goal_objective", views.get_bussniess_goal_objective),
    path(
        "get_bussniess_goal_objective/<int:sid>/<int:pid>/",
        views.get_bussniess_goal_objective,
    ),
    path("upd_bussniess_goal_objective/<int:id>/", views.upd_bussniess_goal_objective),
    path("del_bussniess_goal_objective/<int:id>/", views.del_bussniess_goal_objective),
    # scorecard
    path("ins_scorecard", views.ins_scorecard),
    path("get_scorecard", views.get_scorecard),
    path("get_scorecard/<int:id>/", views.get_scorecard),
    path("get_range_scorecard/<int:start>/<int:end>/", views.get_range_scorecard),
    path("upd_scorecard/<int:id>/", views.upd_scorecard),
    path("del_scorecard/<int:id>/", views.del_scorecard),
    path("val_scorecard", views.val_scorecard),
    path("checking_api", views.checking_api),
    path("get_published_scorecard", views.get_published_scorecard),
    # scorecard Details
    path("ins_scorecard_details", views.ins_scorecard_details),
    path("get_scorecard_details", views.get_scorecard_details),
    path("upd_scorecard_details/<int:id>/", views.upd_scorecard_details),
    path("del_scorecard_details/<int:id>/", views.del_scorecard_details),
    path("get_kpi_else_org_stop_light_indicators/<int:kpi_id>/", views.get_kpi_else_org_stop_light_indicators),
    # KPI Details URLS
    path("ins_kpi_details", views.ins_kpi_details),
    path("get_kpi_details", views.get_kpi_details),
    path("get_kpi_details/<int:sid>/", views.get_kpi_details),
    path("get_kpi_details/<int:sid>/<int:pid>/<int:oid>/", views.get_kpi_details),
    path("get_kpi_details_Kid/<int:kid>/", views.get_kpi_details_Kid),
    path("upd_kpi_details/<int:id>/", views.upd_kpi_details),
    path("del_kpi_details/<int:id>/", views.del_kpi_details),
    # KPI Actuals URLS
    path("ins_kpi_actuals", views.ins_kpi_actuals),
    path("get_kpi_actuals", views.get_kpi_actuals),
    path("upd_kpi_actuals/<int:id>/", views.upd_kpi_actuals),
    path("del_kpi_actuals/<int:id>/", views.del_kpi_actuals),
    path(
        "smp_get_kpi/<str:kpi_id>/<str:sc_id>/<str:prep_id>/<str:obj_id>",
        views.smp_get_kpi,
    ),
    path("smp_get_kpi_new/<str:kpi_id>/", views.smp_get_kpi_new),
    # settings
    path("get_settings", views.get_settings),
    path("get_settings/<int:id>/", views.get_settings),
    path("upd_settings", views.upd_settings),
    path("upd_settings/<int:id>/", views.upd_settings),
    # validation api
    path("val_scorecard", views.val_scorecard),
    path("val_scorecard_details", views.val_scorecard_details),
    path("val_bussniess_goal_objective", views.val_bussniess_goal_objective),
    # Dynamic Filtering urls start
    #     path('get_range_date/<date:start_date>/<date:end_date>/<str:column>/', views.get_range_date),
    # end
    # temp api for testing
    path("temp_api/<int:id>/", views.temp_api),
    # kpi user access
    # path('ins_kpi_user_access', views.ins_kpi_user_access),
    path("get_kpi_user_access", views.get_kpi_user_access),
    # KPI views URL
    # path("get_view/", views.get_view),
    path("get_kpi_with_actuals/", views.get_kpi_with_actuals),
    # KPI Dashboard views URL
    # path("get_kpi_dashboard_view/", views.get_kpi_dashboard_view),
    path("get_kpi_dashboard_view/<int:id>/", views.get_kpi_dashboard_view),
    path("get_curr_prev_actual_score/", views.get_curr_prev_actual_score),
    path("get_curr_prev_actual_score/<int:id>/", views.get_curr_prev_actual_score),
    # path("get_kpi_dashboard_view1/", views.get_kpi_dashboard_view1),
    # path("get_sd_dashboard_view/", views.get_sd_dashboard_view),
    # path("get_obj_dashboard_view/", views.get_obj_dashboard_view),
    # path("get_sc_dashboard_view/", views.get_sc_dashboard_view),
    # Chart Attributes URL
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
    # Dynamic Dashboard URL
    path("get_all_tables", views.get_all_tables),
    path("get_dynamic_trio/<str:tablename>/", views.get_dynamic_trio),
    path("get_dynamic_filtering", views.get_dynamic_filtering),
    # kpi pendings
    path("get_kpi_pending_actions", views.get_kpi_pending_actions),
    path("get_kpi_pending_actions/<int:id>/", views.get_kpi_pending_actions),
    path("upd_flag_kpi_pending_actions/<int:id>/", views.upd_flag_kpi_pending_actions),
    # sli
    path("ins_kpi_sli", views.ins_kpi_sli),
    path("get_kpi_sli", views.get_kpi_sli),
    path("get_range_kpi_sli/<int:start>/<int:end>/", views.get_range_kpi_sli),
    path("upd_kpi_sli/<int:id>/", views.upd_kpi_sli),
    path("del_kpi_sli/<int:id>/", views.del_kpi_sli),
    # Csv uplode
    path("csv_insert/<int:id>/", views.Csv_insert),
    # ! test
    #     path('check_actuals/', views.check_actuals),
    # KPI score Initiative
    path("get_sc_initiative", views.get_sc_initiative),
    path("get_sc_initiative_details", views.get_sc_initiative_details),
    path("ins_sc_initiative", views.ins_sc_initiative),
    #  partial filters for scorecard
    path("scorecard_description/", search_scorecard_description.as_view()),
    path("get_scorecard_details_yet_kpi/<int:id>/", views.get_scorecard_details_yet_kpi),
    path(
        "search_scorecard_description/<int:id>/", views.filter_scorecard_description
    ),
    #  smtp
    path("get_smtp", views.get_smtp),
    path("ins_upt_smtp", views.ins_upt_smtp),
    #  Forgot Password
    path("forgot_password", views.forgot_password),
    path("get_kpi_actuals_monthly_score", views.get_kpi_actuals_monthly_score),
    # Global helper
    path("get_helper/<int:id>/", views.get_helper),
    path("get_helper", views.get_helper),
    # kpi_pin_dashboard
    path("ins_kpi_pin_dashboard", views.ins_kpi_pin_dashboard),
    path("get_kpi_pin_dashboard", views.get_kpi_pin_dashboard),
    path("get_kpi_pin_dashboard/<int:id>/", views.get_kpi_pin_dashboard),
    path("del_kpi_pin_dashboard/<int:id>/", views.del_kpi_pin_dashboard),
    path("upd_kpi_pin_dashboard", views.upd_kpi_pin_dashboard),
    #  vw_kpi_pin_dashboard
    # path("get_vw_kpi_pin_dashboard/", views.get_vw_kpi_pin_dashboard),
    # Scorecard api
    path(
        "api_scorecard_scorecard_details_objective_kpi",
        views.api_scorecard_scorecard_details_objective_kpi,
    ),
    # Global Error Message
    path("get_warnings", views.get_warnings),
    #  scorecard_report_generator
    path("get_scorecard_report_generator", views.get_scorecard_report_generator),
    # Manual query execution functions
    path("get_kpi_details_uom", views.get_kpi_details_uom),
    path("get_kpi_details_uom_2", views.get_kpi_details_uom_2),
    path("get_kpi_details_uom_3/", views.get_kpi_details_uom_3),
    path("get_license", views.get_license),
    path("ins_upd_license/<int:id>/", views.ins_upd_license),
    # Add,Update,Delete Pin Chart to HomePage
    path("ins_pin_chart_homepage", views.ins_chat_pin_homepage),
    path("get_pin_chart_homepage/<int:id>", views.get_chart_pin_dashboard),
    path("upd_pin_chart_homepage", views.upd_chart_pin_dashboard),
    path("upd_order_no", views.update_order_no),
    path("updatesession/<int:uid>/", views.updatesession),
    path("updatesession/<int:uid>/<str:update>/", views.updatesession),
    path("deletesession/<int:uid>/", views.deletesession),

    # session Configuration
    path("getsessionconfig", views.get_session_configuration),
    path("ins_upd_session_config/<int:id>/", views.ins_upd_session_configuration),
    # path("deletesession/<int:uid>/", views.deletesession),
    #
    path("ins_sso", views.ins_sso),
    path("get_sso", views.get_sso),
    path("upd_sso/<int:id>/", views.upd_sso),
    path("notification_and_group", views.notification_and_group),
    path("notification_and_group/<int:user_id>/", views.notification_and_group),
    path("notification_show_handle/<int:id>/", views.notification_show_handle),
    path("notification_kpi_show_handle/<int:id>/", views.notification_kpi_show_handle),
    # User Profile URLS
    path("ins_user_profile", views.ins_user_profile),
    path("get_user_profile", views.get_user_profile),
    path("get_user_profile/<int:id>/", views.get_user_profile),
    path("upd_user_profile/<int:id>/", views.upd_user_profile),
    path("del_user_profile/<int:id>/", views.del_user_profile),

    path("get_rb_db_connect_table", views.get_rb_db_connect_table),
    path("get_rb_db_connect_table/<int:id>/", views.get_rb_db_connect_table),
    path("get_range_rb_db_connect_table/<int:start>/<int:end>/", views.get_range_rb_db_connect_table),
    path("ins_rb_db_connect_table",views.ins_rb_db_connect_table),
    path("rb_test_db_connection",views.rb_test_db_connection),
    path("upd_rb_db_connect_table/<int:id>/", views.upd_rb_db_connect_table),
    path("del_rb_db_connect_table/<int:id>/", views.del_rb_db_connect_table),


    # path("rb_get_conn_str",rb_views.rb_get_conn_str),
    path("set_db_sql_connection",rb_views.set_db_sql_connection),
    path("set_db_oracle_connection",rb_views.set_db_oracle_connection),
    path("get_connected_tables",rb_views.fnGetTableData),
    path("display_columns",rb_views.rb_sql_show_columns),
    path("ins_save_connection_data",rb_views.fnStoreQueryNameConnectionData),
    path("upd_connection_data/<int:id>/", rb_views.fnUpdateQueryNameConnectionData),
    path("get_connection_data",rb_views.fnGetQueryDefinition),
    path("get_connection_data/<int:id>/",rb_views.fnGetQueryDefinition),
    path("get_range_query_definition/<int:start>/<int:end>/<str:created_user>/", rb_views.get_range_query_definition),
    path("get_range_query_definition/<int:start>/<int:end>/<str:created_by>/<str:search>/", rb_views.get_range_query_definition),

    # ? Shared Query URLS
    path("ins_shared_query_definition",rb_views.ins_shared_query_definition),
    path("upd_shared_query_definition/<int:id>/", rb_views.upd_shared_query_definition),
    path("get_shared_query_definition",rb_views.get_shared_query_definition),
    path("get_shared_query_definition/<int:id>/",rb_views.get_shared_query_definition),
    path("get_range_shared_query_definition/<int:start>/<int:end>/<str:permission_to>/", rb_views.get_range_shared_query_definition),
    path("get_range_shared_query_definition/<int:start>/<int:end>/<str:permission_to>/<str:search>/", rb_views.get_range_shared_query_definition),
    
    
    path("ins_save_table_data",rb_views.fnsaveSelectedTables),
    path("get_save_table_data",rb_views.fnGetQueryBuilderTable),
    path("get_save_table_data/<int:id>/",rb_views.fnGetQueryBuilderTable),
    
    path("ins_save_column_data",rb_views.fnsaveSelectedColumn),
    path("get_save_column_data",rb_views.fngetsavedcolumns),
    path("get_save_column_data/<int:id>/",rb_views.fngetsavedcolumns),
    

    path("ins_alias_table_data",rb_views.fn_ins_column_alias),
    path("get_alias_table_data",rb_views.fn_get_column_alias),
    
    
    path("ins_aggregate_table_data",rb_views.fn_ins_column_aggregate),
    path("get_aggregate_table_data",rb_views.fn_get_column_aggregate),
    path("get_aggregate_table_data/<int:id>/",rb_views.fn_get_column_aggregate),

    path("ins_save_join_table_data",rb_views.fninsjointablesave),
    path("get_join_table_data",rb_views.fnGetJoinTableColumnData),
    path("get_join_table_data/<int:id>/",rb_views.fnGetJoinTableColumnData),
    
    path("get_execute_query_data",rb_views.fnpostquerytoexecute),
    
    
    path("ins_query_column_data",rb_views.fn_ins_query_column_data),

    path("get_query_result",rb_views.fnGetQueryResult),
    path("get_countries",views.get_countries),
    path("get_state/<int:id>/",views.get_state),
    path("get_state",views.get_state),
    path("instant_scduler",updater.instant_jobs_scheduler),

    path("get_sharepointData",views.get_sharepointData),
    path("get_computational_details", views.get_computational_details),
    path("chat_bot_index/_search", views._search),
        
]
