import os
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.template.loader import render_to_string

from Portal.models import MessagingQueue, Member, CorporateProfile
from Portal.token import password_reset_token
from Portal.utils import *

import logging, datetime, requests

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_GenerateContractEmail.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_GenerateContractEmail.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def sendEmail():
    try:
        # Get all messages queue that status is False which has not been processed
        getMessages = MessagingQueue.objects.all().filter(status=False, module='GenerateContractView', void=False)
        if getMessages:
            for message in getMessages:
                try:
                    # Check if email exists
                    is_email_exists = Member.objects.filter(email_address=message.email_address, paid=True, rejected=False).exists()
                    getMessageByID = getMessages.get(id=message.id)
                    if is_email_exists:
                        is_multiple_exists = Member.objects.filter(email_address=message.email_address, paid=True, rejected=False).count()
                        if is_multiple_exists <= 1:
                            # Check if retry limit exceeded
                            if message.retry != settings.RETRY_LIMIT:
                                try:
                                    member = Member.objects.get(email_address=message.email_address, paid=True, rejected=False)
                                    company = CorporateProfile.objects.get(id=member.corporate_id)
                                    deartimeDB  = DearTimeDbConn()
                                    isConnected = deartimeDB.connect()
                                    if not isConnected:
                                        logger.error("Connection Lost!")
                                    else:
                                        getMemberProductMapping = MemberProductMapping.objects.filter(member=member, is_terminated=False, is_renewal=False)
                                        attachment_list = {}
                                        if getMemberProductMapping:
                                            for mpm in getMemberProductMapping:
                                                if mpm.deartime_coverageid:
                                                    getCoverageUuid = deartimeDB.exec_SQL('getCoverageUuid', {'COVERAGE_ID': mpm.deartime_coverageid}, 'fetchone')
                                                    getUserUuid     = deartimeDB.exec_SQL('getUserUuid', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                                    encryption      = member.mykad[-4:] + str(member.dob.year)
                                                    app_view        = '2'
                                                    type            = 'contract'
                                                    detailsData     = {
                                                        'app_view'      : app_view,
                                                        'coverage'      : getCoverageUuid['dset'][0],
                                                        'type'          : type,
                                                        'user_id'       : getUserUuid['dset'][0],
                                                        'encryption'    : encryption
                                                    }

                                                    formatURL = settings.DT_CONTRACT_WEB_SERVICE
                                                    for key, value in detailsData.items():
                                                        formatURL = formatURL + key + '=' + value + '&'
                                                    # getResponse     = requests.get('https://holy-grass-9y8yebyjnwuj.vapor-farm-d1.com/doc?app_view=2&coverage=d5acb2a1-d55f-4f38-a416-3ca77693c97a&type=contract&user_id=c9f5ee7a-a882-4b89-82aa-ef076b642992&encryption=29711996')
                                                    logger.error("GenerateContractEmail Formatting URL: " + formatURL)
                                                    getResponse     = requests.get(formatURL)
                                                    path = company.company_name + "/Contract"
                                                    dir = settings.MEDIA_ROOT.replace("\\", "/") + "/" + path
                                                    isExist = os.path.exists(dir)
                                                    if not isExist:
                                                        os.mkdir(dir)
                                                    # file = member.email_address + "_" + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d') + "_" + mpm.product.product_name + ".pdf"
                                                    file = mpm.product.product_name + ".pdf"
                                                    f = open(dir + "/" + file, 'wb')
                                                    f.write(getResponse.content)
                                                    f.close()
                                                    attachment_list[mpm.product.product_name.replace(' ', '_')] = dir + "/" + file

                                    data         = {
                                        'email_body'   : "",
                                        'to_email'     : member.email_address,
                                        'email_subject': "We Got You Covered",
                                    }

                                    data_v2     = {
                                        'email_body'   : "",
                                        'to_email'     : member.email_address,
                                        'email_subject': "DearTime Purchase Completed - DearTime Contract",
                                        'attachment'   : attachment_list
                                    }

                                    getTransactionID = Invoice.objects.filter(company_id=company.id).last()
                                    context = {
                                        'tentative_premium': str(member.tentative_premium),
                                        'transaction_id'   : getTransactionID.senangpay_refno,
                                        'payor_name'       : company.company_name,
                                        'coverages'        : getMemberProductMapping,
                                        'member_name'      : member.name.title()
                                    }
                                    htmlTemplate = render_to_string('EmailTemplate/ContractGenerationEmail.html', context)
                                    htmlTemplate_v2 = render_to_string('EmailTemplate/ContractGenerationEmailv2.html', context)

                                    getSendStatus = GenericLibraries().send_pdf_email(data, htmlTemplate)
                                    getSendStatus_v2 = GenericLibraries().send_pdf_email(data_v2, htmlTemplate_v2)
                                    logger.error("GenerateContractEmail: " + str(getSendStatus))
                                    logger.error("GenerateContractEmail: " + str(getSendStatus_v2))
                                    # If email successfully sent
                                    if getSendStatus_v2 == 1:
                                        getMessageByID.send_datetime = datetime.datetime.now()
                                        getMessageByID.status        = True
                                        getMessageByID.save()
                                    else:
                                        getMessageByID.retry = getMessageByID.retry + 1
                                        getMessageByID.save()
                                    deartimeDB.close()
                                except Exception as e:
                                    logger.error("GenerateContractEmail: " + str(e))
                                    continue
                            else:
                                getMessageByID.void = True
                                getMessageByID.save()
                        else:
                            logger.error("GenerateContractEmail: " + 'Found multiple users are binded to {} in the system.'.format(message.email_address))
                    else:
                        logger.error("GenerateContractEmail: " + '{} not found in the system.'.format(message.email_address))
                except Exception as ex:
                    logger.error(str(ex))
    except Exception as e:
        logger.error("GenerateContractEmail: " + str(e))