
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import get_template, render_to_string

from Portal.models import MessagingQueue, Member, CorporateProfile
from Portal.token import password_reset_token
from Portal.utils import GenericLibraries, DearTimeDbConn

import logging, datetime, os

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_MemberRejectEmail.log"
else:
    monday = datetime.datetime.now() - datetime.timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_MemberRejectEmail.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmailMemberReject():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='MemberRejectEmailView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = Member.objects.filter(email_address=message.email_address, rejected=True).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = Member.objects.filter(email_address=message.email_address, rejected=True).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    member = Member.objects.get(email_address=message.email_address, rejected=True)
                                    user   = CorporateProfile.objects.get(id=member.corporate_id)
                                    relativelink = reverse('corporateportal:login_page')
                                    absurl       = settings.HOST_ADDRESS + relativelink
                                    
                                    context      = {
                                        'payor'   : user.company_name,
                                        'owner'   : member.name,
                                        'Url'     : absurl,
                                        'gender'  : member.gender
                                    }
                                    htmlTemplate = render_to_string('EmailTemplate/MemberRejectEmail.html', context)
                                    
                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : user.email_address,
                                        'email_subject': 'Offer Rejected'
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
        logger.error("MemberRejectEmail: " + str(e))

def sendEmailMedicalSurveyFailed():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='MedicalSurveyFailedEmailView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = Member.objects.filter(email_address=message.email_address, rejected=True).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = Member.objects.filter(email_address=message.email_address, rejected=True).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    member = Member.objects.get(email_address=message.email_address, rejected=True)
                                    user   = CorporateProfile.objects.get(id=member.corporate_id)
                                    
                                    relativelink = reverse('corporateportal:login_page')
                                    absurl       = settings.HOST_ADDRESS + relativelink
                                    
                                    context      = {
                                        'payor'   : user.company_name,
                                        'owner'   : member.name,
                                    }
                                    htmlTemplate = render_to_string('EmailTemplate/MedicalSurveyFailedEmail.html', context)
                                    
                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : user.email_address,
                                        'email_subject': 'Offer Rejected'
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
        logger.error("MemberRejectEmail: " + str(e))

def sendEmailMemberActiveSI():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='MemberActiveSIView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = Member.objects.filter(email_address=message.email_address, si_waitinglist=True, is_deleted=True).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = Member.objects.filter(email_address=message.email_address, rejected=False).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    member      = Member.objects.get(email_address=message.email_address, si_waitinglist=True, is_deleted=True)
                                    user        = CorporateProfile.objects.get(id=member.corporate_id)
                                    deartimeDB  = DearTimeDbConn()
                                    isConnected = deartimeDB.connect()
                                    if not isConnected:
                                        logger.error("Connection Lost!")
                                    else:
                                        getActiveSI = deartimeDB.exec_SQL('getSponsoredInsurance', {'USER_ID' : member.deartime_memberid}, 'fetchone')

                                        if getActiveSI['dset']:

                                            context      = {
                                                'payor'   : user.company_name,
                                                'owner'   : member.name,
                                                'gender'  : member.gender,
                                                'next_renewal_date' : datetime.datetime.strftime(getActiveSI['dset'][1], '%d %B %Y')
                                            }

                                            htmlTemplate = render_to_string('EmailTemplate/MemberActiveSIEmail.html', context)
                                            
                                            data         = {
                                                'email_body'   : "",
                                                'to_email'     : user.email_address,
                                                'email_subject': 'Offer Rejected'
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
                                        
                                        deartimeDB.close()
                                        
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
        logger.error("MemberRejectEmail: " + str(e))