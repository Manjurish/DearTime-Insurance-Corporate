from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import get_template, render_to_string

from Portal.models import MessagingQueue, Member, CorporateProfile
from Portal.token import password_reset_token
from Portal.utils import *

import logging, datetime, os

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_ReminderNotificationEmail.log"
else:
    monday = datetime.datetime.now() - datetime.timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_ReminderNotificationEmail.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    try:
        # Get all messages queue that status is False which has not been process
        getMessages = MessagingQueue.objects.all().filter(status=False, module='MemberInvitationReminderView', void=False)
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
                                        reminder_no =  MessagingQueue.objects.filter(email_address=message.email_address, module='MemberInvitationReminderView', void=False).count()

                                        last_reminder = False
                                        if reminder_no == 5:
                                            last_reminder = True

                                        gender = member.gender.lower()  # Convert to lowercase for case-insensitive comparison

                                        if gender in ['male', 'm']:
                                            pronouns = "him"
                                        elif gender in ['female', 'f']:
                                            pronouns = "her"   

                                        uidb64 = urlsafe_base64_encode(smart_bytes(user.user.id))
                                        memUidb64 = urlsafe_base64_encode(smart_bytes(member.id))
                                        token  = password_reset_token.make_token(user.user)
                                        
                                        referral_code = GenericLibraries.insertReferralCode(user, deartimeDB)
                                        referral_link = GenericLibraries().generateReferralCodeQR(user.company_name, referral_code)
                                        fileDir = os.path.join(settings.BASE_DIR, "media", user.company_name)
                                        file_path = os.path.join(fileDir, f"{user.company_name}.png").replace("\\", "/")
                                        deartimeDB.close()
                                    
                                    context      = {
                                        'payor'               : user.company_name,
                                        'owner'               : member.name,
                                        'reminder_no'         : reminder_no,
                                        'last_reminder'       : last_reminder,
                                        'pronouns'            : pronouns,
                                        'referral_link'       : referral_link,
                                        'referral_qr'         : file_path
                                    }
                                    if member.is_existing:
                                        htmlTemplate = render_to_string('EmailTemplate/ExistingMemberInvitationEmail.html', context)
                                        indicator = None
                                    else:
                                        htmlTemplate = render_to_string('EmailTemplate/NewMemberInvitationEmail.html', context)
                                        indicator = 'ReminderNotficationEmail'
                                        
                                    if member.reminder_count is None or member.reminder_count==0:
                                        member.reminder_count=1

                                    #last reminder will be send to corporate admin
                                    email_address = member.email_address
                                    if last_reminder:
                                        email_address = user.email_address
                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : email_address,
                                        # 'email_subject': 'BUY FOR OTHERS - {payor} Would Like To Purchase Insurance For You - Reminder {count}'.format(payor=user.company_name,count=member.reminder_count)
                                        'email_subject': '{payor} Offers to Buy Insurance for You - Reminder {count}'.format(payor=user.company_name,count=member.reminder_count)
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
        # Get all members that are not accepting the invitation 
        getMembers = Member.objects.all().filter(medical_survey=False, void=False, rejected=False, status='Pending Acceptance')
        if getMembers:
            for members in getMembers:
                #No response on 7 days after 3rd reminder
                # if days_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 15:
                if members.sendinvitation_datetime:
                    #compare the last_reminder date
                    #1st reminder
                    if days_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 7:
                    # if minutes_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 1:
                        if members.reminder_count is None or members.reminder_count < 1:
                            saveMessageQueue = MessagingQueue(
                                email_address = members.email_address,
                                module        = 'MemberInvitationReminderView'
                            )
                            saveMessageQueue.save()
                            members.last_reminder = datetime.datetime.now()
                            members.reminder_count = 1
                            members.save()
                    #2nd reminder
                    elif days_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 14:
                    # elif minutes_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 2:
                        if members.reminder_count is None or members.reminder_count < 2:
                            saveMessageQueue = MessagingQueue(
                                email_address = members.email_address,
                                module        = 'MemberInvitationReminderView'
                            )
                            saveMessageQueue.save()
                            members.last_reminder = datetime.datetime.now()
                            members.reminder_count = 2
                            members.save() 
                    #3rd reminder
                    elif days_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 21:
                    # elif minutes_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 3:
                        if members.reminder_count is None or members.reminder_count < 3:
                            saveMessageQueue = MessagingQueue(
                                email_address = members.email_address,
                                module        = 'MemberInvitationReminderView'
                            )
                            saveMessageQueue.save()
                            members.last_reminder = datetime.datetime.now()
                            members.reminder_count = 3
                            members.save() 
                    
                    #4th reminder
                    elif days_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 28:
                    # elif minutes_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 4:
                        if members.reminder_count is None or members.reminder_count < 4:
                            saveMessageQueue = MessagingQueue(
                                email_address = members.email_address,
                                module        = 'MemberInvitationReminderView'
                            )
                            saveMessageQueue.save()
                            members.last_reminder = datetime.datetime.now()
                            members.reminder_count = 4
                            members.save() 

                    #last reminder
                    elif days_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 31:
                    # elif minutes_between(str(members.sendinvitation_datetime).split(".")[0], str(datetime.datetime.now()).split(".")[0]) == 4:
                        if members.reminder_count is None or members.reminder_count < 5:
                            saveMessageQueue = MessagingQueue(
                                email_address = members.email_address,
                                module        = 'MemberInvitationReminderView'
                            )
                            saveMessageQueue.save()
                            members.last_reminder = datetime.datetime.now()
                            members.reminder_count = 5
                            members.save() 

    except Exception as e:
        logger.error(str(e))

    