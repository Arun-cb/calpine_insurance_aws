from apscheduler.schedulers.background import BackgroundScheduler
# from base.api.views import check_kpi_actulas_pending, check_monthly_actuals_remainder, session_active_check
import os
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from rest_framework.response import Response
from rest_framework import generics, status, filters
from rest_framework.decorators import api_view
from base.models import *

# from base.api.automation.export_file import automationKpiActuals

def jobs_scheduler(id):
    print("jobs_scheduler")
    start(id)
    return Response("Scheduler has been completed", status=status.HTTP_200_OK)

@api_view(["GET"])
def instant_jobs_scheduler(request):
    print("jobs_scheduler")
    # check_kpi_actulas_pending()
    # check_monthly_actuals_remainder()
    # automationKpiActuals()
    return Response("Scheduler has been completed", status=status.HTTP_200_OK)


@api_view(["GET"])
def testinstance(request):
    # automationKpiActuals()
    return Response("Scheduler has been completed", status=status.HTTP_200_OK)

def checking():
    print("This job is checking perpose")

scheduler = BackgroundScheduler()
scheduler.start()
def start(id = 0):
    remainder_time = 43200  # 12 hours
    pending_time = 36000    # 10 hours
    minute=00
    sett=[]
    # scheduler = BackgroundScheduler()
    if id != 0:
        sett = settings.objects.filter(user_id=id).values()
    if len(sett) != 0:
        if sett.filter(variable_name='remaining_scheduler') and len(sett.filter(variable_name='remaining_scheduler')[0]) != 0:
            remainder_time = (sett.filter(variable_name='remaining_scheduler')[0]) if (sett.filter(variable_name='remaining_scheduler')) else remainder_time
            hour_for_remaining=23
            if remainder_time['ampm'] == 'pm':
                if(int(remainder_time['hours']) < 12):
                    hour_for_remaining=int(remainder_time['hours'])+12
                else:
                    hour_for_remaining=int(remainder_time['hours'])
            else:
                hour_for_remaining=int(remainder_time['hours'])

            scheduler.remove_job('kpiRemainder')

            if len(sett) != 0 and remainder_time['types'] == 'monthly':
                # print("monthly", hour_for_remaining, int(remainder_time['seconds']))
                scheduler.add_job(check_monthly_actuals_remainder, 'cron', day=remainder_time['value'], hour=hour_for_remaining, minute=int(remainder_time['seconds']), id='kpiRemainder') 
            elif len(sett) != 0 and remainder_time['types'] == 'weekly':
                scheduler.add_job(check_monthly_actuals_remainder, 'cron', day_of_week=remainder_time['value'].lower(),hour=hour_for_remaining, minute=int(remainder_time['seconds']), id='kpiRemainder')
            elif len(sett) != 0 and remainder_time['types'] == 'days':
                days = int(remainder_time['value'])
                minutes = int(remainder_time['seconds'])
                scheduler.add_job(check_monthly_actuals_remainder, 'interval', days=days, hours=hour_for_remaining, minutes=minutes, id='kpiRemainder')
            else:
                scheduler.add_job(check_monthly_actuals_remainder, 'interval', seconds=int(remainder_time), id='kpiRemainder')
        
        if sett.filter(variable_name='pending_scheduler') and len(sett.filter(variable_name='pending_scheduler')[0]) != 0:
            pending_time = (sett.filter(variable_name='pending_scheduler')[0]) if (sett.filter(variable_name='pending_scheduler')) else pending_time
            hour_for_pending=23
            if pending_time['ampm'] == 'pm':
                if(int(pending_time['hours']) < 12):
                    hour_for_pending=int(pending_time['hours'])+12
                else:
                    hour_for_pending=int(pending_time['hours'])
            else:
                hour_for_pending=int(pending_time['hours'])

            scheduler.remove_job('kpiPending')

            if len(sett) != 0 and pending_time['types'] == 'monthly':
                print("monthly", hour_for_remaining, int(remainder_time['seconds']))
                scheduler.add_job(check_kpi_actulas_pending, 'cron', day=pending_time['value'], hour=hour_for_pending, minute=int(pending_time['seconds']), id='kpiPending')
            elif len(sett) != 0 and pending_time['types'] == 'weekly':
                scheduler.add_job(check_kpi_actulas_pending, 'cron', day_of_week=pending_time['value'].lower(),hour=hour_for_pending, minute=int(pending_time['seconds']), id='kpiPending')
            elif len(sett) != 0 and pending_time['types'] == 'days':
                days = int(pending_time['value'])
                minutes = int(pending_time['seconds'])
                scheduler.add_job(check_kpi_actulas_pending, 'interval', days=days, hours=hour_for_pending, minutes=minutes, id='kpiPending')
            else:
                scheduler.add_job(check_kpi_actulas_pending, 'interval', seconds=int(pending_time), id='kpiPending')
        
        # if id != 0:
            # scheduler.remove_job('checkingId')
            
            # scheduler.add_job(check_kpi_actulas_pending, 'interval', seconds=int(pending_time), id='kpiPending')
            # scheduler.add_job(check_monthly_actuals_remainder, 'interval', seconds=int(remainder_time), id='kpiRemainder')
    else:
        # scheduler.add_job(checking, 'interval', seconds=int(remainder_time), id='checkingId', replace_existing=True)
        scheduler.add_job(check_kpi_actulas_pending, 'interval', seconds=int(pending_time), id='kpiPending') 
        scheduler.add_job(check_monthly_actuals_remainder, 'interval', seconds=int(remainder_time), id='kpiRemainder') 
        scheduler.add_job(session_active_check, 'interval', minutes=15)
    