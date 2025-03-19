import logging
from Portal.utils import *
from Portal.models import *
from django.db import transaction

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_CheckMedicalSurvey.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_CheckMedicalSurvey.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def checkMedicalSurvey():
    try:
        memberQS    = Member.objects.filter(paid=False, medical_survey=False, rejected=False, status='Pending Acceptance')
        for mem in memberQS:
            try:
                deartimeDB  = DearTimeDbConn()
                isConnected = deartimeDB.connect()
                if not isConnected:
                    logger.error("Connection Lost!")
                else:
                    getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID' : mem.deartime_memberid}, 'fetchone')
                    medicalSurveyCreatedAt = deartimeDB.exec_SQL('getMedicalSurveyCreatedDatetime',{'ID':getIndividualID['dset'][0]}, 'fetchone')
                    # check if medical survey created at is greater than send invitation datetime
                    if medicalSurveyCreatedAt['dset']:
                        if medicalSurveyCreatedAt['dset'][0] > mem.sendinvitation_datetime:
                            medicalSurvey = deartimeDB.exec_SQL('validateMedicalSurvey',{'ID':getIndividualID['dset'][0]}, 'fetchone')
                            if medicalSurvey['dset']:
                                productAcceptanceCount = 4
                                terminatedProduct = 0
                                for val in medicalSurvey['dset']:
                                    if val == 0:
                                        terminatedProduct += 1
                                if terminatedProduct == productAcceptanceCount:
                                    mem.status = "Rejected"
                                    mem.rejected_reason = "Rejected by medical survey"
                                    mem.save()
                                    saveMessageQueue = MessagingQueue(
                                        email_address = mem.email_address,
                                        module        = 'MedicalSurveyFailedEmailView'
                                    )
                                    saveMessageQueue.save()
                    deartimeDB.close()
            except Exception as ex:
                logger.error(str(ex))
    except Exception as ex:
        logger.error(str(ex))
