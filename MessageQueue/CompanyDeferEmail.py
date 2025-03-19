from django.urls import reverse
from django.conf import settings
from django.template.loader import render_to_string

from Portal.models import MessagingQueue, CorporateUser, CorporateProfile
from Portal.utils import GenericLibraries

import logging, datetime, os

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_CompanyDeferEmail.log"
else:
    monday = datetime.datetime.now() - datetime.timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_CompanyDeferEmail.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='CompanyDeferEmailView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = CorporateUser.objects.filter(email=message.email_address).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = CorporateUser.objects.filter(email=message.email_address).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    user         = CorporateUser.objects.get(email=message.email_address)
                                    payor        = CorporateProfile.objects.get(email_address=message.email_address)
                                    relativelink = reverse('corporateportal:login_page')
                                    absurl       = settings.HOST_ADDRESS + relativelink
                                    
                                    context      = {
                                        'corporatePayor' : payor.company_name,
                                        'loginUrl'       : absurl,
                                        'rejectReason'   : payor.remarks
                                    }
                                    htmlTemplate = render_to_string('EmailTemplate/CompanyDeferEmail.html', context)
                                    
                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : user.email,
                                        'email_subject': 'DearTime Insurance Corporate Purchase'
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