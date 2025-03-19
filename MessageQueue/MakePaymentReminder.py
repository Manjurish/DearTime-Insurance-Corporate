from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import get_template, render_to_string
from django.db.models import Q

from Portal.models import MessagingQueue, Member, CorporateProfile, Invoice, Order
from Portal.token import password_reset_token
from Portal.utils import GenericLibraries

import logging, datetime, os
from datetime import timedelta

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_MakePaymentReminder.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_MakePaymentReminder.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='MakePaymentReminderView', void=False)
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
                                    user   = CorporateProfile.objects.get(email_address=message.email_address)
                                    memberCount = Member.objects.filter(corporate_id=user.id, generated_invoice=True,paid=False, rejected=False).count()
                                    invoices = Invoice.objects.all().filter(Q(status="Pending Payment",company_id=user.id)|Q(status="Payment In Progress"))
                                    for invoice in invoices:
                                        days = days_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0])
                                        if days == 3 or days == 7 or days == 11:
                                            due_date = (invoice.created_datetime+timedelta(days=15))
                                    due_date = datetime.date.strftime(due_date, "%Y-%m-%d")
                                    relativelink = reverse('corporateportal:login_page')
                                    absurl       = settings.HOST_ADDRESS + relativelink
                                    
                                    context      = {
                                        'payor'               : user.company_name,
                                        'due_date'            : due_date,
                                        'memberCount'         : memberCount,
                                        'invitationUrl'       : absurl
                                    }

                                    htmlTemplate = render_to_string('EmailTemplate/MakePaymentNotification.html', context)
                                    
                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : user.email_address,
                                        'email_subject': 'PAYMENT NOTIFICATION - Please make payment before expired'
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

def days_between(d1, d2):
    d1 = datetime.datetime.strptime(d1, "%Y-%m-%d %H:%M:%S")
    d2 = datetime.datetime.strptime(d2, "%Y-%m-%d %H:%M:%S")
    return abs((d2-d1).days)

def minutes_between(d1, d2):
    d1 = datetime.datetime.strptime(d1, "%Y-%m-%d %H:%M:%S")
    d2 = datetime.datetime.strptime(d2, "%Y-%m-%d %H:%M:%S")
    difference = abs(d2 - d1).total_seconds()
    minutes_in_day = difference/60
    minutes_in_day = int(minutes_in_day)
    return minutes_in_day

def reminder():
    try:
        getInvoice = Invoice.objects.all().filter(Q(status="Pending Payment")|Q(status="Payment In Progress") )
        if getInvoice:
            for invoice in getInvoice:
                company = CorporateProfile.objects.get(id=invoice.company_id)
                #No response on 7 days after 3rd reminder
                #if minutes_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 4:
                if days_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) >= 15:
                    if invoice.status!='Void':
                        member = None
                        # invoice.status = "Void"
                        # invoice.remarks = "Invoice has expired."
                        # invoice.updated_datetime = str(datetime.datetime.now())
                        # invoice.save()
                        getOrderObj = Order.objects.filter(invoice=invoice)
                        for order in getOrderObj:
                            member = Member.objects.get(id=order.member_id, renew=False)
                            if member:
                                member.status = "Expired"
                                member.rejected = True
                                member.generated_invoice = False
                                member.save()
                                GenericLibraries.terminateCoverage(member)
                                GenericLibraries.terminateMemberProductMap(member,None)
                        
                        if member:
                            invoice.status = "Void"
                            invoice.remarks = "Invoice has expired."
                            invoice.updated_datetime = str(datetime.datetime.now())
                            invoice.save()
                        # saveMessageQueue = MessagingQueue(
                        #     email_address = company.email_address,
                        #     module        = 'CompanyPaymentExpiredView'
                        # )
                        # saveMessageQueue.save()
                else:
                    #compare the last_reminder date
                    #1st reminder
                    if days_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 3:
                    #if minutes_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 1:
                        if invoice.payment_reminder is None or invoice.payment_reminder < 1:
                            saveMessageQueue = MessagingQueue(
                                email_address = company.email_address,
                                module        = 'MakePaymentReminderView'
                            )
                            saveMessageQueue.save()
                            invoice.payment_reminder = 1
                            invoice.save()
                    #2nd reminder
                    elif days_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 7:
                    #elif minutes_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 2:
                        if invoice.payment_reminder is None or invoice.payment_reminder < 2:
                            saveMessageQueue = MessagingQueue(
                                email_address = company.email_address,
                                module        = 'MakePaymentReminderView'
                            )
                            saveMessageQueue.save()
                            invoice.payment_reminder = 2
                            invoice.save()
                    #3rd reminder
                    elif days_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 11:
                    #elif minutes_between(str(invoice.created_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 3:
                        if invoice.payment_reminder is None or invoice.payment_reminder < 3:
                            saveMessageQueue = MessagingQueue(
                                email_address = company.email_address,
                                module        = 'MakePaymentReminderView'
                            )
                            saveMessageQueue.save()
                            invoice.payment_reminder = 3
                            invoice.save()

    except Exception as e:
        logger.error(str(e))
