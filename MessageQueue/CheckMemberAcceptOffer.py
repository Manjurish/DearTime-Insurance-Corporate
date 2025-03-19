import logging
from Portal.utils import *
from Portal.models import *
from django.db import transaction

logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_CheckMemberAcceptOffer.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_CheckMemberAcceptOffer.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def memberAcceptedStatus():
    try:
        memberQS    = Member.objects.filter(medical_survey=False, rejected=False, status='Pending Acceptance')
        for mem in memberQS:
            try:
                deartimeDB  = DearTimeDbConn()
                isConnected = deartimeDB.connect()
                if not isConnected:
                    logger.error("Connection Lost!")
                else:
                    try:
                        corporateObj = CorporateProfile.objects.get(id=mem.corporate_id)
                        getIndividualID   = deartimeDB.exec_SQL('getIndividualNRIC', {'NRIC': mem.mykad}, 'fetchone')
                        coverageOfferCount    = deartimeDB.exec_SQL('getCoverageCount', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid}, 'fetchone')
                        acceptedProductCount  = deartimeDB.exec_SQL('getCoverageAcceptedCount', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid}, 'fetchone')                  
                        getIndividualData = deartimeDB.exec_SQL('getIndividualDataNRIC', {'NRIC': mem.mykad}, 'fetchone')

                        
                        if coverageOfferCount['dset'][0] != 0:
                            if acceptedProductCount['dset'][0] > 0:
                                checkCovDict        = {}
                                productKeyFields    = [prd.product_name for prd in Product.objects.filter(is_active=True)]
                                hasTerminated       = False
                                for prod in productKeyFields:
                                    getProductObj = Product.objects.filter(product_name__icontains=prod).first()
                                    if getProductObj:
                                        getDTProductID = deartimeDB.exec_SQL('getProductLIKE', {'PRD_NAME': prod}, 'fetchone')
                                        getProductID = Product.objects.get(product_name__icontains=prod)
                                        getMemberProductMapping = MemberProductMapping.objects.get(member=mem, product=getProductID.id, is_terminated=False)
                                        if getMemberProductMapping.deartime_coverageid:
                                            getCoverageStatus  = deartimeDB.exec_SQL('getProdCoverageStatus', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid, 'PRD_ID' : getDTProductID['dset'][0], 'COVERAGE_ID':getMemberProductMapping.deartime_coverageid}, 'fetchone')
                                            mem.read_datetime = datetime.datetime.now()
                                            mem.save()
                                            if getCoverageStatus['dset']:
                                                if getCoverageStatus['dset'][0] == 'terminate':
                                                    GenericLibraries.terminateMemberProductMap(mem,getProductID.id)
                                                    new_member_product_mapping = MemberProductMapping(
                                                        coverage_amount     = 0,
                                                        member_id           = mem.id,
                                                        product             = getProductObj,
                                                    )
                                                    new_member_product_mapping.save()
                                                    hasTerminated = True
                                                else:
                                                    if prod != 'Medical':
                                                        getProductCoverages = deartimeDB.exec_SQL('getProductCoverage', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID': corporateObj.deartime_payerid, 'PRD_ID': getDTProductID['dset'][0], 'COVERAGE_ID':getMemberProductMapping.deartime_coverageid}, 'fetchone')
                                                    else:
                                                        getProductCoverages = deartimeDB.exec_SQL('getMedicalCoverage', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID': corporateObj.deartime_payerid, 'MEDICAL_PRD_ID': getDTProductID['dset'][0], 'COVERAGE_ID':getMemberProductMapping.deartime_coverageid}, 'fetchone')
                        
                                                    if getProductCoverages['dset']:
                                                        getMemberProductMapping.coverage_amount = getProductCoverages['dset'][0]
                                                        getMemberProductMapping.updated_datetime = datetime.datetime.now()
                                                        getMemberProductMapping.save()
                                if hasTerminated:
                                    saveMessageQueue = MessagingQueue(
                                        email_address = mem.email_address,
                                        module        = 'coveragePartiallyRejectedEmail'
                                    )
                                    saveMessageQueue.save()
                                getUpdatedMemberProductMapping = MemberProductMapping.objects.filter(member=mem, is_terminated=False, is_renewal = False)
                                for mpm in getUpdatedMemberProductMapping:
                                    checkCovDict[mpm.product.product_name] = int(mpm.coverage_amount)
                                checkExistPackage = CheckUniquePackage().check(checkCovDict, corporateObj.user_id, corporateObj.corporate_campaign_code)
                                if checkExistPackage:
                                    mem.package = checkExistPackage
                                else:
                                    new_package = GenericLibraries().addPackageData(corporateObj, corporateObj.user, productKeyFields, checkCovDict)
                                    mem.package = new_package

                                mem.mykad = getIndividualData['dset'][0]
                                mem.dob = getIndividualData['dset'][1]
                                mem.gender = getIndividualData['dset'][2]
                                mem.deartime_memberid = getIndividualData['dset'][3]
                                mem.medical_survey = True
                                mem.status = 'Accept'
                                mem.updated_datetime = datetime.datetime.now()
                                mem.save()
                        deartimeDB.close()     
                    except Exception as ex:
                        logger.error(str(ex))
                        deartimeDB.close() 
            except Exception as ex:
                logger.error(str(ex))
                deartimeDB.close() 
    except Exception as ex:
        logger.error(str(ex))
        deartimeDB.close() 
