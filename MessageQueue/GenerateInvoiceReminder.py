from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import get_template, render_to_string

from Portal.models import MessagingQueue, Member, CorporateProfile
from Portal.token import password_reset_token
from Portal.utils import GenericLibraries
from Portal.utils import *

import logging, datetime, os
from datetime import timedelta,date

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_GenerateInvoiceReminder.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_GenerateInvoiceReminder.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    deartimeDB = DearTimeDbConn()
    isConnected = deartimeDB.connect()
    if not isConnected:
        logger.error("Connection Lost!")
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='GenerateInvoiceReminderView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = CorporateProfile.objects.filter(email_address=message.email_address, rejected=False).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = CorporateProfile.objects.filter(email_address=message.email_address, rejected=False).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    user = CorporateProfile.objects.get(email_address=message.email_address,rejected=False)
                                    members = Member.objects.filter(corporate_id=user.id,rejected=False,status='Accept')
                                    memberCount = Member.objects.filter(corporate_id=user.id, status='Accept', rejected=False).count()
                                    due_date = None
                                    remindercount = 0
                                    for member in members:                                        
                                        getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                        getMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False, is_renewal=False).exclude(deartime_coverageid__isnull=True)
                                        for mpm in getMemberProductMapping:
                                            acceptDateTime  = deartimeDB.exec_SQL('getCoverageUpdateTime', {'INDIVIDUAL_ID': getIndividualID['dset'][0], 'COVERAGE_ID':mpm.deartime_coverageid}, 'fetchone')
                                        due_date = (acceptDateTime['dset'][0] + timedelta(days=181))                          
                                        formated_due_date = datetime.date.strftime(due_date, "%Y-%m-%d")
                                        if member.invoice_reminder_count and member.invoice_reminder_count != 0:
                                            remindercount = member.invoice_reminder_count

                                    lastreminder = False
                                    if remindercount == 5:
                                        lastreminder = True
                                    
                                    relativelink = reverse('corporateportal:login_page')
                                    absurl       = settings.HOST_ADDRESS + relativelink
                                    
                                    context      = {
                                        'payor'               : user.company_name,
                                        'memberCount'         : memberCount,
                                        'due_date'            : formated_due_date,
                                        'reminder_no'         : remindercount,
                                        'last_reminder'       : lastreminder,
                                        'invitationUrl'       : absurl
                                    }
                                    
                                    htmlTemplate = render_to_string('EmailTemplate/GenerateInvoiceNotification.html', context)

                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : user.email_address,
                                        'email_subject': 'GENERATE INVOICE REMINDER - Please generate invoice before expired'
                                    }

                                    getSendStatus = GenericLibraries().send_alternative_email(data, htmlTemplate)

                                    #If email successfully sent
                                    if getSendStatus == 1:
                                        getMessageByID.send_datetime = datetime.datetime.now()
                                        getMessageByID.status        = True
                                        getMessageByID.save()
                                    else:
                                        getMessageByID.retry = getMessageByID.retry + 1
                                        getMessageByID.save()
                                except Exception as e:
                                    logger.error(str(e))
                                    continue
                            else:
                                getMessageByID.void = True
                                getMessageByID.save()
                        else:
                            logger.error('Found multiple users are binded to {} in the system.'.format(message.email_address))
                    else:
                        logger.error('{} not found in the system.'.format(message.email_address))
                except Exception as ex:
                    logger.error(str(ex))
    except Exception as e:
        logger.error(str(e))

def reminder():
    deartimeDB = DearTimeDbConn()
    isConnected = deartimeDB.connect()
    if not isConnected:
        logger.error("Connection Lost!")
    try:
        # Calculate the start of the day (midnight)
        start_of_day = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        # Calculate the end of the day (just before midnight)
        end_of_day = start_of_day + timedelta(days=1)

        corporateUsers   = CorporateProfile.objects.filter(status = 'Verified', rejected = False)

        if corporateUsers:
            for user in corporateUsers:
                emailRequestToday = MessagingQueue.objects.filter(email_address= user.email_address, module='GenerateInvoiceReminderView', void=False, request_datetime__gte=start_of_day, request_datetime__lt=end_of_day).count()
                reminderCount = 0
                if emailRequestToday == 0:
                    # Get all members that accept the invitation 
                    getMembers = Member.objects.all().filter(corporate_id=user.id, void=False, rejected=False, generated_invoice=False, is_deleted=False, status='Accept')
                    if getMembers:
                        for members in getMembers:
                            getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID': members.deartime_memberid}, 'fetchone')
                            getMemberProductMapping = MemberProductMapping.objects.filter(member_id=members.id, is_terminated=False, is_renewal=False).exclude(deartime_coverageid__isnull=True)
                            for mpm in getMemberProductMapping:
                                acceptDateTime  = deartimeDB.exec_SQL('getCoverageUpdateTime', {'INDIVIDUAL_ID': getIndividualID['dset'][0], 'COVERAGE_ID':mpm.deartime_coverageid}, 'fetchone')
                            getCompany = CorporateProfile.objects.get(id=members.corporate_id)
                            #No response on 7 days after 3rd reminder
                            # if settings.ENVIRONMENT_INDICATOR != '':
                            #     preferredCurrentDate = CurrentDate.objects.filter(corporate_id=members.corporate_id)
                            #     if preferredCurrentDate:
                            #         currentObject = CurrentDate.objects.get(corporate_id=members.corporate_id)
                            #         currentDate = currentObject.current_datetime
                            #     else:
                            #         currentDate = datetime.datetime.today()
                            # else:
                            #     currentDate = datetime.datetime.today()
                            currentDate = datetime.datetime.today()
                            if acceptDateTime:
                                time_difference = (currentDate.date() - acceptDateTime['dset'][0].date()).days + 1
                                if time_difference == 181:
                                    if members.status!='Expired':
                                        members.status = "Expired"
                                        members.rejected = True
                                        members.rejected_reason = "Offer Expired"
                                        members.medical_survey = False
                                        members.invoice_reminder_count = 0
                                        members.save()
                                        GenericLibraries.terminateCoverage(members)
                                        GenericLibraries.terminateMemberProductMap(members,None)
                                        
                                else:
                                    #compare the last_reminder date
                                    #1st reminder
                                    if time_difference == 7:
                                        if members.invoice_reminder_count is None or members.invoice_reminder_count < 1:
                                            reminderCount += 1
                                            members.last_reminder = datetime.datetime.now()
                                            members.invoice_reminder_count = 1
                                            members.save()
                                    #2nd reminder
                                    elif time_difference == 14:
                                        if members.invoice_reminder_count is None or members.invoice_reminder_count < 2:
                                            reminderCount += 1
                                            members.last_reminder = datetime.datetime.now()
                                            members.invoice_reminder_count = 2
                                            members.save() 
                                    #3rd reminder
                                    elif time_difference == 21:
                                        if members.invoice_reminder_count is None or members.invoice_reminder_count < 3:
                                            reminderCount += 1
                                            members.last_reminder = datetime.datetime.now()
                                            members.invoice_reminder_count = 3
                                            members.save()
                                    #4th reminder
                                    elif time_difference == 28:                       
                                        if members.invoice_reminder_count is None or members.invoice_reminder_count < 4:
                                            reminderCount += 1
                                            members.last_reminder = datetime.datetime.now()
                                            members.invoice_reminder_count = 4
                                            members.save()
                                    #last reminder
                                    #elif days_between(str(acceptDateTime['dset'][0]).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 31:  
                                    elif time_difference == 31:                     
                                        if members.invoice_reminder_count is None or members.invoice_reminder_count < 5:
                                            reminderCount += 1
                                            members.last_reminder = datetime.datetime.now()
                                            members.invoice_reminder_count = 5
                                            members.save()

                        if reminderCount > 0:
                            saveMessageQueue = MessagingQueue(
                                email_address = user.email_address,
                                module        = 'GenerateInvoiceReminderView'
                            )
                            saveMessageQueue.save()

    except Exception as e:
        logger.error(str(e))

    