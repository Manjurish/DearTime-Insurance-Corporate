from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import get_template, render_to_string
from django.db.models import Q

from Portal.models import MessagingQueue, Member, CorporateProfile, Invoice, Order
from Portal.token import password_reset_token
from Portal.utils import *

import logging, datetime, os
from datetime import timedelta

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_CoverageRenewalNotification.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_CoverageRenewalNotification.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='CoverageRenewalNotification', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = CorporateProfile.objects.filter(email_address=message.email_address, rejected=False).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = CorporateProfile.objects.filter(email_address=message.email_address, rejected=False).count()
                        user           = CorporateProfile.objects.get(email_address=message.email_address)
                        paymentDueDate = user.payment_due_date
                        paymentDueDate = datetime.datetime.strptime(paymentDueDate, '%Y-%m-%d')
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    if user:
                                        deartimeDB  = DearTimeDbConn()
                                        isConnected = deartimeDB.connect()
                                        if not isConnected:
                                            logger.error("Connection Lost!")    
                                        activeMemberRenewal = Member.objects.filter(Q(Q(status='Active') & Q(renew=False) & Q(paid = True)) | Q(Q(status__in=['Pending Payment', 'P.Invoice']) & Q(renew=True) & Q(paid = False)), corporate_id=user.id, rejected=False)
                                        isReminder = True
                                        afterPDD = False
                                        emailSubject = 'Coverage Renewal - Reminder'
                                        invoiceDate = 15
                                        if activeMemberRenewal:
                                            recipients = {}
                                            for member in activeMemberRenewal:
                                                getMemberIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                                getPayerID = CorporateProfile.objects.get(id=member.corporate_id)
                                                memberCoverage = deartimeDB.exec_SQL('getCoveragesDates', {'OWNER_ID': getMemberIndividualID['dset'][0], 'PAYER_ID': getPayerID.deartime_payerid}, 'fetchone')
                                                firstIndex = memberCoverage['dcolname'].index('first_payment_on')
                                                first_payment_on = memberCoverage['dset'][firstIndex]
                                                currentDate = GenericLibraries().currentDateTesting(getPayerID.id)
                                                consecutive_years = abs(relativedelta(currentDate,first_payment_on).years)
                                                time_difference = (paymentDueDate.date() - currentDate.date()).days + 1
                                                year_difference = currentDate.year - paymentDueDate.year
                                                if year_difference < 0:
                                                    paymentDueDate = paymentDueDate.replace(year=currentDate.year)
                                                    overdueTime = (currentDate.date() - paymentDueDate.date()).days
                                                else:
                                                    overdueTime = (currentDate.date() - paymentDueDate.date()).days

                                                # Check if the absolute difference is either 10 days or 3 days
                                                if getPayerID.payment_mode == 'Monthly':
                                                    if time_difference == 2:
                                                        isReminder = False
                                                        emailSubject = 'Coverage Renewal'
                                                else:
                                                    if time_difference == 10:
                                                        isReminder = False
                                                        emailSubject = 'Coverage Renewal'

                                                if overdueTime > 0:
                                                    afterPDD = True                                                 
                                                
                                                # Send generate invoice reminder email after intervals of 7 days from the payment due date
                                                if overdueTime % 7 == 0:
                                                    if consecutive_years < 2:
                                                        if 15 < overdueTime <= 31:
                                                            invoiceDate = min(invoiceDate, 30 - overdueTime)
                                                    else:
                                                        if 75 < overdueTime <= 91:
                                                            invoiceDate = min(invoiceDate, 90 - overdueTime)
                                                    #     if overdueTime <= 30 and overdueTime > 15:
                                                    #         invoiceDate = 30 - overdueTime
                                                             # invoiceDate = (paymentDueDate + timedelta(days=30) - datetime.datetime.now()).days
                                                    # else:
                                                    #     if overdueTime <= 90 and overdueTime > 75:
                                                    #         invoiceDate = 90 - overdueTime
                                                            # invoiceDate = (paymentDueDate + timedelta(days=90) - datetime.datetime.now()).days
                                                recipients[user.email_address] = {
                                                    'isReminder'  : isReminder,
                                                    'afterPDD'    : afterPDD,
                                                    'emailSubject': emailSubject,
                                                }

                                            for recipient_email, recipient_data in recipients.items():
                                                # Send the email to the recipient with the combined data for all members
                                                context = {
                                                    'payor': user.company_name,
                                                    'premiumDD': paymentDueDate,
                                                    'invoiceDate' : invoiceDate,
                                                    **recipient_data  # Include 'isReminder' and 'emailSubject' from the recipient_data
                                                }
                                                htmlTemplate = render_to_string('EmailTemplate/CoverageRenewalNotification.html', context)

                                                data = {
                                                    'email_body': "",
                                                    'to_email': recipient_email,
                                                    'email_subject': recipient_data['emailSubject'],
                                                }

                                                getSendStatus = GenericLibraries().send_alternative_email(data, htmlTemplate)

                                                # If email successfully sent
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


def terminateMemberInvoice(member, graceCoverage, deartimeDB):
    status_dict = {
        'grace-unpaid': 'deactivated',
        'grace-increase-unpaid': 'deactivated',
        'active': 'deactivated',
        'active-increased': 'deactivated',
    }
    for cvg in graceCoverage['dset']:
        for status, new_status in status_dict.items():
            coverages = {'NEW_STATUS': new_status, 'COVERAGE_ID': cvg[0], 'ORIGINAL_STATUS': status}
            deartimeDB.exec_SQL('updateCoveragesFulfilled', coverages, 'update')
            
    allMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False)
    if allMemberProductMapping:
        for allMPM in allMemberProductMapping:
            allMPM.is_terminated = True
            allMPM.save()   
    
    if member.generated_invoice:
        getOrderObj     = Order.objects.filter(member_id = member.id).latest('created_datetime')
        if getOrderObj:
            try:
                getInvoice  = Invoice.objects.filter(id=getOrderObj.invoice_id, status__in=['Pending Payment', 'Payment In Progress']).latest('created_datetime')
                if getInvoice:
                    getInvoice.status  = "Void"
                    getInvoice.remarks = "Invoice not generated within alocated time period."
                    getInvoice.updated_datetime = str(datetime.datetime.now())
                    getInvoice.save()
            except Invoice.DoesNotExist:
                pass
            
    member.status = 'Deactivated'
    member.generated_invoice = False
    member.medical_survey = False
    member.renew = False
    member.void = True
    member.save()
    
        
def voidInvoice(member):
    member.status = 'Pending Payment'
    member.generated_invoice = False
    member.save()
    getOrderObj     = Order.objects.filter(member_id = member.id).latest('created_datetime')
    if getOrderObj:
        getInvoiceObj = Invoice.objects.filter(id=getOrderObj.invoice_id, status__in=['Pending Payment', 'Payment In Progress'])
        if getInvoiceObj:
            getInvoice  = Invoice.objects.get(id=getOrderObj.invoice_id, status__in=['Pending Payment', 'Payment In Progress'])
            getInvoice.status  = "Void"
            getInvoice.remarks = "Invoice not generated within alocated time period."
            getInvoice.updated_datetime = str(datetime.datetime.now())
            getInvoice.save()
        
def sendReminderEmail(email_address):
    saveMessageQueue = MessagingQueue(
        email_address = email_address,
        module        = 'CoverageRenewalNotification'
        )
    saveMessageQueue.save()
    
def reminder():
    try:
        # Calculate the start of the day (midnight)
        start_of_day = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        # Calculate the end of the day (just before midnight)
        end_of_day = start_of_day + timedelta(days=1)
        
        corporateUsers   = CorporateProfile.objects.filter(status = 'Verified', rejected = False)
        if corporateUsers:
            deartimeDB  = DearTimeDbConn()
            isConnected = deartimeDB.connect()
            if not isConnected:
                logger.error("Connection Lost!")
            for user in corporateUsers:
                # Check if reminder email has been sent today
                paymentDueDate = user.payment_due_date
                paymentDueDate = datetime.datetime.strptime(paymentDueDate, '%Y-%m-%d')
                emailRequestToday = MessagingQueue.objects.filter(email_address= user.email_address, module='CoverageRenewalNotification', void=False, request_datetime__gte=start_of_day, request_datetime__lt=end_of_day).count()
                reminderCount = 0
                if emailRequestToday == 0:
                    activeMemberRenewal = Member.objects.filter(Q(Q(status='Active') & Q(renew=False) & Q(paid = True)) | Q(Q(status__in=['Pending Payment', 'P.Invoice']) & Q(renew=True) & Q(paid = False)), corporate_id=user.id, rejected=False)
                    if activeMemberRenewal:
                        for member in activeMemberRenewal:
                            getMemberIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID': member.deartime_memberid}, 'fetchone')
                            getCorporateObj = CorporateProfile.objects.get(id=member.corporate_id)
                            memberCoverage = deartimeDB.exec_SQL('getCoveragesDates', {'OWNER_ID': getMemberIndividualID['dset'][0], 'PAYER_ID': getCorporateObj.deartime_payerid}, 'fetchone')
                            if memberCoverage['dset']:
                                graceCoverage = deartimeDB.exec_SQL('getGraceCoverage', {'OWNER_ID': getMemberIndividualID['dset'][0], 'PAYER_ID': getCorporateObj.deartime_payerid}, 'fetchall')
                                firstIndex = memberCoverage['dcolname'].index('first_payment_on')
                                first_payment_on = memberCoverage['dset'][firstIndex]
                                currentDate = GenericLibraries().currentDateTesting(getCorporateObj.id)
                                consecutive_years = abs(relativedelta(currentDate,first_payment_on).years)
                                time_difference = (paymentDueDate.date() - currentDate.date()).days + 1
                                year_difference = currentDate.year - paymentDueDate.year
                                if year_difference < 0:
                                    paymentDueDate = paymentDueDate.replace(year=currentDate.year)
                                    overdueTime = (currentDate.date() - paymentDueDate.date()).days
                                else:
                                    overdueTime = (currentDate.date() - paymentDueDate.date()).days
                                if not member.generated_invoice:
                                    if getCorporateObj.payment_mode == 'Monthly':
                                        # Send reminder email
                                        # 2 days before the PDD or On the PDD if there is no payment received
                                        if time_difference == 2 or time_difference == 1:
                                            reminderCount += 1

                                        elif overdueTime <= 30 and overdueTime >= 0:
                                            if overdueTime % 5 == 0:
                                                reminderCount += 1
                                            elif overdueTime == 29:
                                                reminderCount += 1

                                        elif consecutive_years < 2:
                                            # modifications 28 October 2024
                                            # change requests 
                                            # change the overdue time from 131 days to 161 days
                                            # modifications 29 October 2024
                                            # change the overdue time from 161 days to 181 days
                                            if overdueTime >= 181:
                                                # Terminate member if no invoice is generated after grace period is over
                                                terminateMemberInvoice(member, graceCoverage, deartimeDB)
                                        else:
                                            if overdueTime >= 91:
                                                # Terminate member if no invoice is generated after grace period is over
                                                terminateMemberInvoice(member, graceCoverage, deartimeDB)
                                        
                                    else:
                                        # Check if there is 10 days or 3 days between payment due date and current datetime
                                        if time_difference == 10 or time_difference == 3:
                                            reminderCount += 1
                                        
                                        # Send generate invoice reminder email after intervals of 7 days from the payment due date
                                        elif consecutive_years < 2:
                                            if overdueTime <= 30 and overdueTime >= 0:
                                                if overdueTime % 7 == 0:
                                                    reminderCount += 1
                                            
                                            # modifications 28 October 2024
                                            # change requests 
                                            # change the overdue time from 131 days to 161 days
                                            # modifications 29 October 2024
                                            # change the overdue time from 161 days to 181 days
                                            elif overdueTime >= 181:
                                                # Terminate member if no invoice is generated after grace period is over
                                                terminateMemberInvoice(member, graceCoverage, deartimeDB)
                                        else:
                                            if overdueTime <= 90 and overdueTime >= 0:
                                                if overdueTime <= 35 or (overdueTime - 35) % 14 == 0:
                                                    reminderCount += 1
                                                    
                                            elif overdueTime >= 91:
                                                # Terminate member if no invoice is generated after grace period is over 
                                                terminateMemberInvoice(member, graceCoverage, deartimeDB)
                                            
                                elif member.generated_invoice and member.paid == False:
                                    invoiceDate = 15
                                    memberOrder = Order.objects.filter(member_id = member.id).latest('created_datetime')
                                    if memberOrder:
                                        memberInvoiceObj = Invoice.objects.filter(id=memberOrder.invoice_id, status__in=['Pending Payment', 'Payment In Progress'])
                                        if memberInvoiceObj:
                                            memberInvoice = Invoice.objects.get(id=memberOrder.invoice_id, status__in=['Pending Payment', 'Payment In Progress'])
                                            if consecutive_years < 2:
                                                if 15 < overdueTime <= 31:
                                                    invoiceDate = min(invoiceDate, 30 - overdueTime)
                                            else:
                                                if 75 < overdueTime <= 91:
                                                    invoiceDate = min(invoiceDate, 90 - overdueTime)
                                            
                                            invoiceGenerationDeadline = memberInvoice.created_datetime
                                            invoiceGenerationDeadline = invoiceGenerationDeadline + timedelta(days=invoiceDate)
                                            
                                            if invoiceGenerationDeadline.date() <= currentDate.date():
                                                if consecutive_years < 2:
                                                    # modifications 28 October 2024
                                                    # change requests 
                                                    # change the overdue time from 131 days to 161 days
                                                    # modifications 29 October 2024
                                                    # change the overdue time from 161 days to 181 days
                                                    if overdueTime >= 181:
                                                        # Terminate member if no payment is made after grace period is over
                                                        terminateMemberInvoice(member, graceCoverage, deartimeDB)
                                                    else:
                                                        # void invoice if no payment is made but grace period is not passed
                                                        voidInvoice(member)
                                                else:
                                                    if overdueTime > 90:
                                                        # Terminate member if no payment is made after grace period is over
                                                        terminateMemberInvoice(member, graceCoverage, deartimeDB)
                                                    else:
                                                        # void invoice if no payment is made but grace period is not passed
                                                        voidInvoice(member)
                                                    
                        if reminderCount > 0:
                            sendReminderEmail(user.email_address)

                            
            deartimeDB.close()
                              
    except Exception as e:
        logger.error(str(e))
