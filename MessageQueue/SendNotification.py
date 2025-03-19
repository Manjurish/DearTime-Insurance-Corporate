import logging, os
from Portal.utils import *
from Portal.models import *
from django.db import transaction

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_SendNotification.log"
else:
    monday = datetime.datetime.now() - datetime.timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_SendNotification.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendNotification():
    try:
        getMessages = MessagingQueue.objects.filter(status=False, module='MemberInvitationApp', void=False)
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
                            if message.retry < settings.RETRY_LIMIT:
                                try:
                                    getMember = Member.objects.get(void=False, email_address=message.email_address, rejected=False)
                                    existing_notif_text = "Hi {owner}, {payor} would like to buy DearTime's insurance for you. If you accept, please proceed to complete the application process."
                                    # if getMember.is_existing:
                                    deartimeDB  = DearTimeDbConn()
                                    isConnected = deartimeDB.connect()
                                    if not isConnected:
                                        logger.error("Connection Lost!")
                                    else:
                                        getIndividualUuid = deartimeDB.exec_SQL('getIndividualUuid', {'USER_ID': getMember.deartime_memberid}, 'fetchone')
                                        getUserUuid = deartimeDB.exec_SQL('getUserUuid', {'USER_ID': CorporateProfile.objects.get(id=getMember.corporate_id).deartime_payerid}, 'fetchone')
                                        if getIndividualUuid['dset']:
                                            dataDict = {
                                                'id'                    : 'pay_other',
                                                'data'                  : 'policies_page',
                                                'buttons'               : [{'title': 'accept', 'action': 'accept_pay_other'}, {'title': 'reject', 'action': 'reject_pay_other_confirm'}],
                                                'command'               : 'next_page',
                                                'auto_read'             : False,
                                                'page_data'             : {
                                                    'user_id'           : getIndividualUuid['dset'][0],
                                                    'payer_id'          : getUserUuid['dset'][0],
                                                    'fill_type'         : 'pay_for_others'
                                                },
                                                'auto_answer'           : True,
                                                'remind_after'          : 3,
                                                'auto_reminder'         : True,
                                                'translate_data'        : {
                                                    'coverages'         : '',
                                                    'payer_name'        : CorporateProfile.objects.get(id=getMember.corporate_id).company_name,
                                                    'owner_name'        : getMember.name
                                                },
                                                'auto_answer_details'   : {
                                                    'days'              : 5,
                                                    'action'            : 'reject_pay_other_confirm'
                                                }
                                            }
                                        # dataNF = (str(uuid.uuid4()), getMember.deartime_memberid, 'Owner Agreement', existing_notif_text.format(owner=getMember.name, payor=CorporateProfile.objects.get(id=getMember.corporate_id).company_name), existing_notif_text.format(owner=getMember.name, payor=CorporateProfile.objects.get(id=getMember.corporate_id).company_name), json.dumps(dataDict), 0, 0, 1, str(datetime.datetime.now()), str(datetime.datetime.now()))
                                        dataNF = (str(uuid.uuid4()), getMember.deartime_memberid, 'mobile.owner_agreement', 'mobile.corporate_payor_offer', 'mobile.corporate_payor_offer', json.dumps(dataDict), 0, 0, 1, str(datetime.datetime.now()), str(datetime.datetime.now()))

                                        notification = deartimeDB.exec_SQL('insertNotification', dataNF, 'insert')
                                        getMessageByID.send_datetime = datetime.datetime.now()
                                        getMessageByID.status        = True
                                        getMessageByID.save()
                                        getMember.status = 'Pending Acceptance'

                                        deartimeDB.close()
                                except Exception as e:
                                    getMessageByID.retry += 1
                                    getMessageByID.save()
                            else:
                                getMessageByID.void = True
                                getMessageByID.save()
                        else:
                            logger.error('Found multiple users are binded to {} in the system.'.format(message.email_address))
                    else:
                        logger.error('{} not found in the system.'.format(message.email_address))
                except Exception as ex:
                    logger.error(str(ex))
    except Exception as ex:
        logger.error(str(ex))

def sendNotificationSponsoredInsurance():
    try:
        getMessages = MessagingQueue.objects.filter(status=False, module='SIMemberInvitationApp', void=False)
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
                            if message.retry < settings.RETRY_LIMIT:
                                try:
                                    getMember = Member.objects.get(void=False, email_address=message.email_address, rejected=False)
                                    existing_notif_text = "Hi {owner}, {payor} is offering to buy DearTime insurance for you. If you accept the offer, your current Sponsored Insurance application will be cancelled. Do you wish to accept? By accepting, please be informed that you will need to re-take the medical survey again. Also, in the event {payor} discontinues the premium payment you will need to re-apply to be sponsored again."
                                    deartimeDB  = DearTimeDbConn()
                                    isConnected = deartimeDB.connect()
                                    if not isConnected:
                                        logger.error("Connection Lost!")
                                    else:
                                        getIndividualUuid = deartimeDB.exec_SQL('getIndividualUuid', {'USER_ID': getMember.deartime_memberid}, 'fetchone')
                                        getUserUuid = deartimeDB.exec_SQL('getUserUuid', {'USER_ID': CorporateProfile.objects.get(id=getMember.corporate_id).deartime_payerid}, 'fetchone')
                                        if getIndividualUuid['dset']:
                                            dataDict = {
                                                'id'                    : 'pay_other',
                                                'data'                  : 'policies_page',
                                                'buttons'               : [{'title': 'accept', 'action': 'accept_payeroffer_confirm_spo'}, {'title': 'reject', 'action': 'reject_pay_other_confirm'}],
                                                'command'               : 'next_page',
                                                'auto_read'             : False,
                                                'page_data'             : {
                                                    'user_id'           : getIndividualUuid['dset'][0],
                                                    'payer_id'          : getUserUuid['dset'][0],
                                                    'fill_type'         : 'pay_for_others'
                                                },
                                                'auto_answer'           : True,
                                                'remind_after'          : 3,
                                                'auto_reminder'         : True,
                                                'translate_data'        : {
                                                    'coverages'         : '',
                                                    'payer_name'        : CorporateProfile.objects.get(id=getMember.corporate_id).company_name,
                                                    'owner_name'        : getMember.name
                                                },
                                                'auto_answer_details'   : {
                                                    'days'              : 5,
                                                    'action'            : 'reject_pay_other_confirm'
                                                }
                                            }
                                        # dataNF = (str(uuid.uuid4()), getMember.deartime_memberid, 'Owner Agreement', existing_notif_text.format(owner=getMember.name, payor=CorporateProfile.objects.get(id=getMember.corporate_id).company_name), existing_notif_text.format(owner=getMember.name, payor=CorporateProfile.objects.get(id=getMember.corporate_id).company_name), json.dumps(dataDict), 0, 0, 1, str(datetime.datetime.now()), str(datetime.datetime.now()))
                                        dataNF = (str(uuid.uuid4()), getMember.deartime_memberid, 'mobile.owner_agreement', 'mobile.corporate_offer_withspo', 'mobile.corporate_offer_withspo', json.dumps(dataDict), 0, 0, 1, str(datetime.datetime.now()), str(datetime.datetime.now()))
                                        notification = deartimeDB.exec_SQL('insertNotification', dataNF, 'insert')
                                        getMessageByID.send_datetime = datetime.datetime.now()
                                        getMessageByID.status        = True
                                        getMessageByID.save()
                                        getMember.status = 'Pending Acceptance'
                                        
                                        deartimeDB.close()
                                except Exception as e:
                                    getMessageByID.retry += 1
                                    getMessageByID.save()
                            else:
                                getMessageByID.void = True
                                getMessageByID.save()
                        else:
                            logger.error('Found multiple users are binded to {} in the system.'.format(message.email_address))
                    else:
                        logger.error('{} not found in the system.'.format(message.email_address))
                except Exception as ex:
                    logger.error(str(ex))
    except Exception as ex:
        logger.error(str(ex))

def ekycNotification():
    try:
        getMessages = MessagingQueue.objects.filter(status=False, module='MemberEkycApp', void=False)
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
                            if message.retry < settings.RETRY_LIMIT:
                                try:
                                    getMember = Member.objects.get(void=False, email_address=message.email_address, rejected=False)
                                    existing_notif_text = "By verifying your MyKad/passport with a selfie, you will be able to enjoy: 1) buy insurance for yourself and others 2) be nominated as beneficiary 3) be our Referrer 4) be sponsored for Sponsored Insurance (T&C apply) 5) Enjoy Time Tube benefits (coming soon)"
                                    # if getMember.is_existing:
                                    deartimeDB  = DearTimeDbConn()
                                    isConnected = deartimeDB.connect()
                                    if not isConnected:
                                        logger.error("Connection Lost!")
                                    else:
                                        getIndividualUuid = deartimeDB.exec_SQL('getIndividualUuid', {'USER_ID': getMember.deartime_memberid}, 'fetchone')
                                        getUserUuid = deartimeDB.exec_SQL('getUserUuid', {'USER_ID': CorporateProfile.objects.get(id=getMember.corporate_id).deartime_payerid}, 'fetchone')
                                        if getIndividualUuid['dset']:
                                            dataDict = {
                                                'id'                    : 'verification',
                                                'data'                  : 'verification_page',
                                                'buttons'               : ["verify_now", "cancell"],
                                                'command'               : 'next_page',
                                                'auto_read'             : False
                                            }
                                        dataNF = (str(uuid.uuid4()), getMember.deartime_memberid, 'mobile.verification_notification_title', 'mobile.verification_notification_body', 'mobile.verification_notification_body', json.dumps(dataDict), 0, 0, 1, str(datetime.datetime.now()), str(datetime.datetime.now()))

                                        notification = deartimeDB.exec_SQL('insertNotification', dataNF, 'insert')
                                        getMessageByID.send_datetime = datetime.datetime.now()
                                        getMessageByID.status        = True
                                        getMessageByID.save()
                                        
                                        deartimeDB.close()
                                except Exception as e:
                                    getMessageByID.retry += 1
                                    getMessageByID.save()
                            else:
                                getMessageByID.void = True
                                getMessageByID.save()
                        else:
                            logger.error('Found multiple users are binded to {} in the system.'.format(message.email_address))
                    else:
                        logger.error('{} not found in the system.'.format(message.email_address))
                except Exception as ex:
                    logger.error(str(ex))
    except Exception as ex:
        logger.error(str(ex))