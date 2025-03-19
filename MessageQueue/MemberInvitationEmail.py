from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import render_to_string

from Portal.models import MessagingQueue, Member, CorporateProfile
from Portal.token import password_reset_token
from Portal.utils import *

import logging, datetime, os

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_MemberInvitationEmail.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_MemberInvitationEmail.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    try:
        # Get all messages queue that status is False which has not been processed
        getMessages = MessagingQueue.objects.all().filter(status=False, module='MemberInvitationView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = Member.objects.filter(email_address=message.email_address, rejected=False).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = Member.objects.filter(email_address=message.email_address, rejected=False).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    deartimeDB = DearTimeDbConn()
                                    isConnected = deartimeDB.connect()
                                    if not isConnected:
                                        logger.error("Connection Lost!")
                                    else:
                                        member = Member.objects.get(email_address=message.email_address, rejected=False)
                                        user   = CorporateProfile.objects.get(id=member.corporate_id)
                                        referral_code = GenericLibraries.insertReferralCode(user, deartimeDB)
                                        referral_link = GenericLibraries().generateReferralCodeQR(user.company_name, referral_code)
                                        fileDir = os.path.join(settings.BASE_DIR, "media", user.company_name)
                                        file_path = os.path.join(fileDir, f"{user.company_name}.png").replace("\\", "/")
                                        deartimeDB.close()
                                        
                                        context      = {
                                            'payor'               : user.company_name,
                                            'owner'               : member.name,
                                            'referral_link'       : referral_link,
                                            'referral_qr'         : file_path
                                            # 'invitationUrl'       : absurl
                                        }
                                        if member.is_existing:
                                            # deartimeDB  = DearTimeDbConn()
                                            # isConnected = deartimeDB.connect()
                                            # if not isConnected:
                                            #     logger.error("Connection Lost!")
                                            # else:
                                            #     userOS = deartimeDB.exec_SQL('getUserOS', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                            #     if userOS['dset'][0] == 'android':
                                            #         context['mobileAppUrl'] = 'https://play.google.com/store/apps/details?id=com.deartime&pli=1'
                                            #     else:
                                            #         context['mobileAppUrl'] = 'https://apps.apple.com/my/app/deartime/id1623745306'
                                            if member.siwaiting_email:
                                                htmlTemplate = render_to_string('EmailTemplate/SponsoredInsuranceMemberInvitationEmail.html', context)
                                            else:
                                                htmlTemplate = render_to_string('EmailTemplate/ExistingMemberInvitationEmail.html', context)
                                            indicator = None
                                        else:
                                            htmlTemplate = render_to_string('EmailTemplate/NewMemberInvitationEmail.html', context)
                                            indicator = 'MemberInvitationEmail'
                                        data         = {
                                            'email_body'   : "",
                                            'to_email'     : member.email_address,
                                            'email_subject': '{payor} Offers to Buy Insurance For You'.format(payor=user.company_name)
                                        }

                                        getSendStatus = GenericLibraries().send_alternative_email(data, htmlTemplate, indicator, user.company_name)

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