from email.encoders import encode_base64
import json, re
import logging, os, hashlib, hmac, requests
from django.conf import settings
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.core import serializers
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.template.loader import get_template
from .models import *
from django.db.models import Q
import mysql.connector, string
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from random import randint

from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.staticfiles import finders
from django.db import transaction
from functools import lru_cache
from sequences import get_next_value
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
from calendar import monthrange, isleap, mdays
from num2words import num2words
from xhtml2pdf import pisa
from django.utils.crypto import get_random_string
from decimal import Decimal,ROUND_HALF_UP

# for qr code generation and styling
from firebase_dynamic_links import DynamicLinks
from PIL import Image, ImageDraw
from qrcode.image.styles.moduledrawers.pil import CircleModuleDrawer
from qrcode.image.styledpil import StyledPilImage
import qrcode as qr
from time import time
from math import ceil

import uuid, datetime, math, calendar, base64, decimal

logging.basicConfig
logger = logging.getLogger(__name__)

class GenericLibraries():
    @staticmethod
    def send_email(data):
        try:
            if 'cc_email' in data:
                email = EmailMessage(
                    subject = data['email_subject'], 
                    body    = data['email_body'], 
                    to      = [data['to_email']],
                    cc      = [data['cc_email']]
                )
            else:
                email = EmailMessage(
                    subject = data['email_subject'], 
                    body    = data['email_body'], 
                    to      = [data['to_email']]
                )
                
            getEmailResponse = email.send()
            return getEmailResponse
        except:
            return 0 # Fail to send
    
    def getCompanyProfile(request):
        companyProfile  = CorporateProfile.objects.get(user_id=request.user.id)
        return companyProfile

    @lru_cache()
    def image_data(image_path, header):
        with open(finders.find(image_path), 'rb') as f:
            image_data = f.read()
        image = MIMEImage(image_data)
        image.add_header('Content-ID',header)
        return image

    @lru_cache()
    def pdf_data(fileName, pdf_path):
        with open(pdf_path, 'rb') as f:
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(f.read())
        encode_base64(attachment)
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename="{filename}".format(filename=pdf_path.split("/")[-1])
        )      
        return attachment

    @lru_cache()
    def qr_image_data(image_path, header):
        full_image_path = os.path.join(settings.MEDIA_ROOT, image_path).replace("\\", "/")
        with open(full_image_path, 'rb') as f:
            image_data = f.read()
        image = MIMEImage(image_data)
        image.add_header('Content-ID',header)
        return image
        
    @staticmethod
    def send_alternative_email(data, htmlTemplate, indicator=None, company_name=None):
        try:
            if 'cc_email' in data:
                email = EmailMultiAlternatives(
                    subject = data['email_subject'], 
                    body    = data['email_body'], 
                    to      = [data['to_email']],
                    cc      = [data['cc_email']]
                )
            else:
                email = EmailMultiAlternatives(
                    subject = data['email_subject'], 
                    body    = data['email_body'], 
                    to      = [data['to_email']]
                )

            email.attach_alternative(htmlTemplate, "text/html")
            email.attach(GenericLibraries.image_data('portal/img/facebook.png','<facebook>'))
            email.attach(GenericLibraries.image_data('portal/img/twitter.png','<twitter>'))
            email.attach(GenericLibraries.image_data('portal/img/instagram.png','<instagram>'))
            email.attach(GenericLibraries.image_data('portal/img/youtube.png','<youtube>'))
            email.attach(GenericLibraries.image_data('portal/img/logo.png','<logo>'))
            if indicator:
                email.attach(GenericLibraries.qr_image_data(company_name+ '/' +company_name+ '.png','<referralQR>'))
                # email.attach(GenericLibraries.image_data('qrcode/AppStore.png','<appstore>'))
                # email.attach(GenericLibraries.image_data('qrcode/AppStoreButton.png','<appstorebtn>'))
                # email.attach(GenericLibraries.image_data('qrcode/PlayStore.png','<playstore>'))
                # email.attach(GenericLibraries.image_data('qrcode/PlayStoreButton.png','<playstorebtn>'))
            getEmailResponse = email.send()
            return getEmailResponse
        except Exception as e:
            logger.error(str(e))
            return 0 # Fail to send

    @staticmethod
    def send_pdf_email(data, htmlTemplate):
        try:
            email = EmailMultiAlternatives(
                subject = data['email_subject'], 
                body    = data['email_body'], 
                to      = [data['to_email']]
            )
            if 'attachment' in data:   
                for prd, att in data['attachment'].items():
                    email.attach(GenericLibraries.pdf_data(prd, att))
                
            email.attach_alternative(htmlTemplate, "text/html")
            email.attach(GenericLibraries.image_data('portal/img/facebook.png','<facebook>'))
            email.attach(GenericLibraries.image_data('portal/img/twitter.png','<twitter>'))
            email.attach(GenericLibraries.image_data('portal/img/instagram.png','<instagram>'))
            email.attach(GenericLibraries.image_data('portal/img/youtube.png','<youtube>'))
            email.attach(GenericLibraries.image_data('portal/img/logo.png','<logo>'))

            getEmailResponse = email.send()
            return getEmailResponse
        except Exception as e:
            logger.error(str(e))
            return 0 # Fail to send

    def saveMessageQueue(email, module):
        saveMsgQueueObj = MessagingQueue(
                email_address = email,
                module        = module
        )
        saveMsgQueueObj.save()
        return saveMsgQueueObj

    def registerCompany(data, companyID):
        with transaction.atomic():
            
            getCompanyInfo = CorporateProfile.objects.get(id=companyID)
            country_code = "+60"
            #Formatting mobile number
            concat_mobile_number = data.POST['companyCountryCode_post'] + data.POST['companyTelephone_post']
            formatted_mobile_number = re.sub('[^0-9+]+', '', str(concat_mobile_number))    
            if country_code in formatted_mobile_number:
                formatted_mobile_number = formatted_mobile_number[2:]
            getCompanyInfo.contact1         = formatted_mobile_number
            getCompanyInfo.contact2         = data.POST['companyTelephone_post']
            getCompanyInfo.address_line1    = data.POST['companyAddress1_post']
            getCompanyInfo.address_line2    = data.POST['companyAddress2_post']
            getCompanyInfo.address_line3    = data.POST['companyAddress3_post']
            getCompanyInfo.state            = data.POST['companyState_post']
            getCompanyInfo.city             = data.POST['companyCity_post']
            getCompanyInfo.postcode         = data.POST['companyPostcode_post']
            getCompanyInfo.payment_due_date = data.POST['paymentDueDate_post']
            getCompanyInfo.payment_mode     = data.POST['paymentMode_post']
            getCompanyInfo.save()

        return getCompanyInfo

    def updateCompanySubmittedStatus(getCompanyInfo):
        getCompanyInfo.submitted        = True
        getCompanyInfo.status           = 'Document Submitted'
        getCompanyInfo.save()
        return getCompanyInfo

    def saveCompanyRelationship(data, getCompanyInfo):
        with transaction.atomic():
            saveRelationshipObj = CompanyRelationship(
                company              = getCompanyInfo,
                relationship_type_id = data.POST['relationship_post'],
                created_by_id        = getCompanyInfo.user_id
            )
            saveRelationshipObj.save()

        return saveRelationshipObj

    def deleteUploadedDoc(data, getCompanyInfo, getRelationship, getSQLConnection):
        CorporateProfileFormAttachment.objects.filter(company_id=data.POST['companyID']).delete()
        CompanyRelationship.objects.filter(company_id=data.POST['companyID']).delete()
        context = {
            'company_info': getCompanyInfo,
            'relationship': getRelationship,
            'cities'      : getSQLConnection.queryCity(),
            'postal_codes': getSQLConnection.queryPost(),
            'states'      : getSQLConnection.queryState(),
            'host_address' : settings.HOST_ADDRESS,
            'http_host_address': settings.HTTP_HOST_ADDRESS
        }
        return context

    def deleteCoverage(request, new_package):
        getDeleteArr    = request.POST["deleteArr"]
        prepDeleteArr   = getDeleteArr.split(",")
        for dlt in prepDeleteArr:
            getMapping  = PackageProductMapping.objects.get(package_id=new_package.id, product_id=Product.objects.get(is_active=True, product_name=dlt).id)
            getMapping.coverage_amount = 0
            getMapping.save()

    def checkCPFOExistMember(self, emailAddress, mobileNo, nric, campaignCode, getUserCorporateObj):
        # checkExistEmailOrMobileOrNric = Member.objects.filter(Q(email_address=emailAddress) | Q(mobile_no=mobileNo) | Q(mykad=nric), is_deleted=False, corporate_id=getUserCorporateObj.id).count()
        checkExistEmailOrMobileOrNric = Member.objects.filter(Q(email_address=emailAddress) | Q(mobile_no=mobileNo) | Q(mykad=nric)  | Q(campaign_code=campaignCode), is_deleted=False).count()

        if checkExistEmailOrMobileOrNric >=1:
            # checkExistEmailOrMobileOrNricwithCorporateId = Member.objects.filter(email_address=emailAddress , mobile_no=mobileNo , mykad=nric, is_deleted=False)
            # if checkExistEmailOrMobileOrNricwithCorporateId:
            #     for match in checkExistEmailOrMobileOrNricwithCorporateId:
            #         if match.corporate_id == getUserCorporateObj.id:
            #             return False
            # else:
            #     return False
            return False
        else:
            return True
            # checkExistMember = Member.objects.filter(email_address=emailAddress, mobile_no=mobileNo, mykad=nric, rejected=False, corporate_id=getUserCorporateObj.id).count()
            # checkTerminatedMember = Member.objects.filter(email_address=emailAddress, mobile_no=mobileNo, mykad=nric, void=False,corporate_id=getUserCorporateObj.id).count()
            # checkIsDeletedMember = Member.objects.filter(email_address=emailAddress, mobile_no=mobileNo, mykad=nric, is_deleted=False,corporate_id=getUserCorporateObj.id).count()
            # if checkExistMember >= 1 or checkTerminatedMember >= 1 or checkIsDeletedMember >= 1:
            #     return False
            # else:
            #     return False

    def checkActiveMedical(self, deartimeDB, getIndividual, medicalCoverage):
        # Check existing medical coverage
        if int(medicalCoverage) != 0: 
            getMedicalProductId = deartimeDB.exec_SQL('getProductLIKE', {'PRD_NAME': 'Medical'}, 'fetchone')
            checkExistingMedical = deartimeDB.exec_SQL('validateMedicalCoverage', {'INDIVIDUAL_ID': getIndividual['dset'][0], 'MEDICAL_PRD_ID': getMedicalProductId['dset'][0]}, 'fetchone')
            if checkExistingMedical['dset']:
                return True
            else:
                return False

    def insertUserToDTDB(self, deartimeDB, memberID):
        getMember = Member.objects.get(id=memberID)
        getUserCorporateObj  = CorporateProfile.objects.get(id=getMember.corporate_id)
        getLatestID  = deartimeDB.exec_SQL('selectMaxIDUserTB', {}, 'fetchone')
        nextLatestID = getLatestID['dset'][0] + 1
        userRefNo    = 'CU' + str(nextLatestID).zfill(6)
        dataDicts    = (userRefNo, str(uuid.uuid4()), 'individual', '', getMember.email_address, str(uuid.uuid4()), 1, str(datetime.datetime.now()), str(datetime.datetime.now()), getUserCorporateObj.deartime_payerid)
        insertDTUser = deartimeDB.exec_SQL('insertUser', dataDicts, 'insert')
        if 'error' in insertDTUser:
            hasError = True   
        else:
            memberID     = insertDTUser['lastID']
            dataIndividual = (str(uuid.uuid4()), insertDTUser['lastID'], getMember.name.upper(), getMember.mykad, getMember.mobile_no, getMember.gender, getMember.dob, getMember.nationality, str(datetime.datetime.now()), str(datetime.datetime.now()))
            insertDTIndividual = deartimeDB.exec_SQL('insertIndividualMember', dataIndividual, 'insert')
            return memberID

    def insertCoverageToDTDB(self, deartimeDB, memberID, getIndividualID):
        getProducts  = Product.objects.filter(is_active=True)
        getMedicalPlans = GetMedicalPlans()
        medical_deductibles = getMedicalPlans.getMedical(deartimeDB)
        getMember = Member.objects.get(id=memberID)
        getUserCorporateObj  = CorporateProfile.objects.get(id=getMember.corporate_id)
        if getMember.renew:
            getNewMappings  = PackageProductMapping.objects.filter(package=getMember.package)
            if getNewMappings:
                for nmpg in getNewMappings:   
                    new_member_product_mapping = MemberProductMapping(
                        coverage_amount     = nmpg.coverage_amount,
                        created_datetime    = datetime.datetime.now(),
                        member_id           = getMember.id,
                        product             = nmpg.product,
                        is_renewal          = True
                    )
                    new_member_product_mapping.save()
        for prds in getProducts:
            getMemberProductMapping = MemberProductMapping.objects.get(member=getMember, product=prds, is_terminated=False, is_renewal = getMember.renew)    
            if int(getMemberProductMapping.coverage_amount) != 0:
                getLatestIDCG  = deartimeDB.exec_SQL('selectMaxIDCoverages', {}, 'fetchone')
                nextLatestIDCG = getLatestIDCG['dset'][0] + 1
                coveragesRefNo = 'CG' + str(nextLatestIDCG).zfill(6)

                getProductID     = deartimeDB.exec_SQL('getProductObj', {'PRD_NAME': prds.product_name.title()}, 'fetchone')
                getExistCoverage = deartimeDB.exec_SQL('validateCoverage', {'USER_ID': getMember.deartime_memberid, 'PRODUCT_NAME': prds.product_name.title()}, 'fetchone')
                parent_id = 0

                if getUserCorporateObj.payment_mode == 'Monthly':
                    paymentTerm = 'monthly'
                else:
                    paymentTerm = 'annually'
                payment_term_new = paymentTerm

                if getExistCoverage['dset']:
                    if getMember.renew:
                        getChangePaymentMode = PaymentModeHistory.objects.filter(corporate_id=getUserCorporateObj.id, is_updated=False, is_void=False)
                        if getChangePaymentMode:
                            latestChangePaymentMode = PaymentModeHistory.objects.latest("created_datetime")
                            payment_mode = latestChangePaymentMode.new_payment_mode
                            if payment_mode == 'Monthly':
                                paymentTerm = 'monthly'
                            else: 
                                paymentTerm = 'annually'
                            payment_term_new = paymentTerm
                        getExistCoverage = deartimeDB.exec_SQL('validateRenewalCoverage', {'USER_ID': getMember.deartime_memberid, 'PAYER_ID': getUserCorporateObj.deartime_payerid,'PRODUCT_NAME': prds.product_name.title()}, 'fetchone')
                        if getExistCoverage['dset'][3] == 'active':
                            new_status = 'grace-unpaid'
                        elif getExistCoverage['dset'][3] == 'active-increased':
                            new_status = 'grace-increased-unpaid'
                        parent_id = getExistCoverage['dset'][0]
                    else:
                        new_status = 'increase-unpaid'
                        parent_id = getExistCoverage['dset'][0]

                    dataDictsCG = (coveragesRefNo, getMemberProductMapping.coverage_amount if prds.product_name.title() != 'Medical' else (medical_deductibles.index(int(getMemberProductMapping.coverage_amount)) + 1), 0, getUserCorporateObj.deartime_payerid, parent_id, str(uuid.uuid4()), getProductID['dset'][0], 0, prds.product_name.title(), 0, getIndividualID['dset'][0], getIndividualID['dset'][0], paymentTerm, payment_term_new, new_status, str(datetime.datetime.now()), str(datetime.datetime.now()), 0 if prds.product_name.title() != 'Medical' else getMemberProductMapping.coverage_amount, str(getUserCorporateObj.payment_due_date), 1, "#"+str(randint(0, 999999)).zfill(6))
                else:
                    dataDictsCG = (coveragesRefNo, getMemberProductMapping.coverage_amount if prds.product_name.title() != 'Medical' else (medical_deductibles.index(int(getMemberProductMapping.coverage_amount)) + 1), 0, getUserCorporateObj.deartime_payerid, 0, str(uuid.uuid4()), getProductID['dset'][0], 0, prds.product_name.title(), 0, getIndividualID['dset'][0], getIndividualID['dset'][0], paymentTerm, payment_term_new, 'unpaid', str(datetime.datetime.now()), str(datetime.datetime.now()), 0 if prds.product_name.title() != 'Medical' else getMemberProductMapping.coverage_amount, str(getUserCorporateObj.payment_due_date), 1, "#"+str(randint(0, 999999)).zfill(6))
                
                DTcoverageID = deartimeDB.exec_SQL('insertCoverages', dataDictsCG, 'insert')
            
                getMemberProductMapping.deartime_coverageid = DTcoverageID['lastID']
                getMemberProductMapping.updated_datetime = datetime.datetime.now()
                getMemberProductMapping.save() 

    def addPackageData(self, getUserCorporateObj, user, productKeyFields, coverages):
        createPackage = Package(
            package_name = 'Customized-' + str(get_next_value(sequence_name=getUserCorporateObj.company_name+"_package/")).zfill(3),
            created_by   = user
        )
        createPackage.save()

        productData = []
        productDict = {}
        for prd in productKeyFields:
            getProductObj = Product.objects.filter(product_name__icontains=prd).first()
            if getProductObj:
                if coverages[prd] != "None":
                    productDict.update({
                        'package'        : createPackage,
                        'product'        : getProductObj,
                        'coverage_amount': int(coverages[prd]),
                        'created_by'     : user
                    })
                    productData.append(
                        PackageProductMapping(**productDict)
                    )
            
        if productData:
            with transaction.atomic():
                PackageProductMapping.objects.bulk_create(productData)

        return createPackage

    def editPackageData(getUserCorporateObj, request, productKeyFields, packageID):
        createPackage = Package(
            package_name = 'Customized-' + str(get_next_value(sequence_name=getUserCorporateObj.company_name+"_package/")).zfill(3),
            created_by   = request.user
        )
        createPackage.save()

        productData = []
        productDict = {}
        for prd in productKeyFields:
            getProductObj = Product.objects.filter(product_name__icontains=prd).first()
            if getProductObj:
                if request.POST[packageID+"_"+prd+"_editMemberPOST"] != "None":
                    productDict.update({
                        'package'        : createPackage,
                        'product'        : getProductObj,
                        'coverage_amount': int(request.POST[packageID+"_"+prd+"_editMemberPOST"]),
                        'created_by'     : request.user
                    })
                    productData.append(
                        PackageProductMapping(**productDict)
                    )
            
        if productData:
            with transaction.atomic():
                PackageProductMapping.objects.bulk_create(productData)

        return createPackage
    
    def saltEncode(self, companyObj):
        message = settings.SALT_HASH + str(companyObj.id)
        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message

    def checkSIWaitingList(self, deartimeDB, memberID):
        data = []
        getSIWaitingList = deartimeDB.exec_SQL('getSponsoredInsuranceWaitingList', {'USER_ID': memberID}, 'fetchone')
        if getSIWaitingList['dset']:
            data.append(getSIWaitingList['dset'][0])
        return data
    
    def terminateMemberProductMap(member,product):
        if product:
            memberProductMap = MemberProductMapping.objects.get(member_id=member.id,product_id=product,is_terminated=False)
            if memberProductMap:
                memberProductMap.is_terminated = True
                memberProductMap.updated_datetime = datetime.datetime.now()
                memberProductMap.save()
                return memberProductMap
        else:
            getProducts = Product.objects.all().filter(is_active=True)
            for product in getProducts:
                memberProductMap = MemberProductMapping.objects.get(member_id=member.id,product_id=product.id,is_terminated=False)
                if memberProductMap:
                    memberProductMap.is_terminated = True
                    memberProductMap.updated_datetime = datetime.datetime.now()
                    memberProductMap.save()
        return memberProductMap
    
    def terminateCoverage(member):
        deartimeDB = DearTimeDbConn()
        isConnected = deartimeDB.connect()
        if not isConnected:
            logger.error("Connection Lost!")
        else:
            getCoverages = MemberProductMapping.objects.filter(member_id=member.id,is_terminated=False)
            for coverage in getCoverages:
                deartime_coverageid = coverage.deartime_coverageid
                if deartime_coverageid:
                    terminateCoverage = deartimeDB.exec_SQL('updateCovMpmTerminate', {'DEARTIME_COVERAGE_ID': deartime_coverageid}, 'update')
            deartimeDB.close()

    def memberAcceptedStatus(self, deartimeDB, corporateObj):
        try:
            memberQS    = Member.objects.filter(medical_survey=False, rejected=False, status='Pending Acceptance', corporate=corporateObj)
            for mem in memberQS:
                try:
                    corporateObj = CorporateProfile.objects.get(id=mem.corporate_id)
                    getIndividualID   = deartimeDB.exec_SQL('getIndividualNRIC', {'NRIC': mem.mykad}, 'fetchone')
                    coverageOfferCount    = deartimeDB.exec_SQL('getCoverageCount', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid}, 'fetchone')
                    acceptedProductCount  = deartimeDB.exec_SQL('getCoverageAcceptedCount', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid}, 'fetchone')                  
                    getIndividualData = deartimeDB.exec_SQL('getIndividualDataNRIC', {'NRIC': mem.mykad}, 'fetchone')

                    try:
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
                                                        getProductCoverages = deartimeDB.exec_SQL('getProductCoverage', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID': corporateObj.deartime_payerid, 'PRD_ID': getDTProductID['dset'][0]}, 'fetchone')
                                                    else:
                                                        getProductCoverages = deartimeDB.exec_SQL('getMedicalCoverage', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID': corporateObj.deartime_payerid, 'MEDICAL_PRD_ID': getDTProductID['dset'][0]}, 'fetchone')
                        
                                                    if getProductCoverages['dset']:
                                                        getMemberProductMapping.coverage_amount = getProductCoverages['dset'][0]
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
                                checkExistPackage = CheckUniquePackage().check(checkCovDict, corporateObj.user_id)
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
                    except Exception as ex:
                        logger.error("CheckAcceptedMember: " + str(ex))
                except Exception as ex:
                        logger.error("CheckAcceptedMember: " + str(ex))
        except Exception as ex:
            logger.error("CheckAcceptedMember: " + str(ex))

    def activeSponsoredInsurance(self, deartimeDB, corporateObj):
        try:
            memberQS    = Member.objects.filter(paid=False, rejected=False, void=False, is_deleted=False, si_waitinglist=True, corporate=corporateObj)
            for mem in memberQS:
                try:
                    getActiveSI     = deartimeDB.exec_SQL('getSponsoredInsurance', {'USER_ID' : mem.deartime_memberid}, 'fetchone')
                    if getActiveSI['dset']:
                        corporateObj = CorporateProfile.objects.get(id=mem.corporate_id)

                        getIndividual     = deartimeDB.exec_SQL('getIndividual', {'USER_ID' : mem.deartime_memberid}, 'fetchone')
                        deartimeDB.exec_SQL('updateCancelledCoverage', {'OWNER_ID': getIndividual['dset'][0], 'PAYER_ID': corporateObj.deartime_payerid}, 'update')
                        mem.status = "Rejected"
                        mem.is_deleted = True
                        mem.rejected_reason = "Insured with DearTime"
                        mem.updated_datetime = datetime.datetime.now()
                        mem.save()
                        GenericLibraries.terminateMemberProductMap(mem,None)
                        saveMessageQueue = MessagingQueue(
                            email_address = mem.email_address,
                            module        = 'MemberActiveSIView'
                        )
                        saveMessageQueue.save()
                except Exception as ex:
                    logger.error(str(ex))
        except Exception as ex:
            logger.error(str(ex))

    def coverageStatus(self, deartimeDB, corporateObj):
        try:
            memberQS    = Member.objects.filter(paid=False, medical_survey=False, rejected=False, status="Pending Acceptance",  corporate=corporateObj)
            for mem in memberQS:
                try:
                    corporateObj = CorporateProfile.objects.get(id=mem.corporate_id)
                    getTerminatedCoverage = MemberProductMapping.objects.filter(member=mem, is_terminated=True)
                    terminateCoverage = []
                    formattedTerminatedCoverage = ''
                    count = 1
                    if getTerminatedCoverage:
                        for coverage in getTerminatedCoverage:
                            if coverage.deartime_coverageid:
                                terminateCoverage.append(coverage.deartime_coverageid)
                        for tcov in terminateCoverage:
                            if count == len(terminateCoverage):
                                formattedTerminatedCoverage += str(tcov)
                            else:
                                formattedTerminatedCoverage += str(tcov) + ','
                            count+=1
                    else:
                        formattedTerminatedCoverage = "''"   

                    getIndividual     = deartimeDB.exec_SQL('getIndividual', {'USER_ID' : mem.deartime_memberid}, 'fetchone')
                    getCoverageStatus = deartimeDB.exec_SQL('getCoverageCount', {'OWNER_ID': getIndividual['dset'][0], 'PAYER_ID': corporateObj.deartime_payerid}, 'fetchone')
                    # terminatedProductCount  = deartimeDB.exec_SQL('getCoverageRejectedCount', {'OWNER_ID': getIndividual['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid, 'COVERAGE_ID':formattedTerminatedCoverage }, 'fetchone')
                    productKeyFields    = [prd.product_name for prd in Product.objects.filter(is_active=True)]
                    getMemberProductWithCoverage = MemberProductMapping.objects.filter(member=mem, is_terminated=False, is_renewal=False).exclude(coverage_amount=0).count()
                    terminatedProduct = 0
                    for prod in productKeyFields:
                        getDTProductID = deartimeDB.exec_SQL('getProductLIKE', {'PRD_NAME': prod}, 'fetchone')
                        getProductID = Product.objects.get(product_name__icontains=prod)
                        getMemberProductMapping = MemberProductMapping.objects.get(member=mem, product=getProductID.id, is_terminated=False, is_renewal=False)
                        if getMemberProductMapping.deartime_coverageid:
                            getCoverageStatusAndCoverage  = deartimeDB.exec_SQL('getProdCoverageStatus', {'OWNER_ID': getIndividual['dset'][0], 'PAYER_ID' : corporateObj.deartime_payerid, 'PRD_ID' : getDTProductID['dset'][0], 'COVERAGE_ID':getMemberProductMapping.deartime_coverageid}, 'fetchone')
                            if getCoverageStatusAndCoverage['dset'][0] == "terminate":
                                terminatedProduct+=1
                    if getCoverageStatus['dset'][0] != 0:
                    #     if terminatedProductCount['dset'][0] > 0:
                        if terminatedProduct==getMemberProductWithCoverage:
                            # deleteCoverages = deartimeDB.exec_SQL('deleteCoverages', {'OWNER_ID': getIndividual['dset'][0]}, 'delete')
                            mem.status = "Rejected"
                            mem.rejected = True
                            mem.rejected_reason = "Rejected by member"
                            mem.save()
                            GenericLibraries.terminateMemberProductMap(mem,None)
                            saveMessageQueue = MessagingQueue(
                                email_address = mem.email_address,
                                module        = 'MemberRejectEmailView'
                            )
                            saveMessageQueue.save()
                except Exception as ex:
                    logger.error(str(ex))
        except Exception as ex:
            logger.error(str(ex))

    def checkMedicalSurvey(self, deartimeDB, getCompanyObj):
        try:
            memberQS    = Member.objects.filter(paid=False, medical_survey=False, rejected=False, status='Pending Acceptance', corporate=getCompanyObj)
            for mem in memberQS:
                try:
                    getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID' : mem.deartime_memberid}, 'fetchone')
                    #rejectMember = deartimeDB.exec_SQL('validateFailedMedicalSurvey',{'ID':getIndividualID['dset'][0]}, 'fetchone')
                    medicalSurvey = deartimeDB.exec_SQL('validateMedicalSurvey',{'ID':getIndividualID['dset'][0]}, 'fetchone')
                    if medicalSurvey['dset']:
                        productAcceptanceCount = 4
                        terminatedProduct = 0
                        for val in medicalSurvey['dset']:
                            if val == 0:
                                terminatedProduct += 1
                        if terminatedProduct == productAcceptanceCount:
                            mem.status = "Rejected"
                            mem.rejected = True
                            mem.rejected_reason = "Rejected by medical survey"
                            mem.save()
                            saveMessageQueue = MessagingQueue(
                                email_address = mem.email_address,
                                module        = 'MedicalSurveyFailedEmailView'
                            )
                            saveMessageQueue.save()
                except Exception as ex:
                    logger.error(str(ex))
        except Exception as ex:
            logger.error(str(ex))
    
    def checkPassMedicalSurvey(self, deartimeDB, getCompanyObj):
        try:
            memberQS    = Member.objects.filter(Q(rejected_reason="Rejected by medical survey") | Q(rejected_reason="Coverage not eligible due to member's medical / occupational profile"), paid=False, medical_survey=False, rejected=True, corporate=getCompanyObj)
            for mem in memberQS:
                try:
                    getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID' : mem.deartime_memberid}, 'fetchone')
                    rejectMember = deartimeDB.exec_SQL('validatePassedMedicalSurvey',{'ID':getIndividualID['dset'][0]}, 'fetchone')
                    if rejectMember['dset']:
                        mem.status = "Pending Acceptance"
                        mem.rejected = False
                        mem.rejected_reason = None
                        mem.save()
                except Exception as ex:
                    logger.error(str(ex))
        except Exception as ex:
            logger.error(str(ex))
            
    def insertReferralCode(getCompanyObj, deartimeDB):
        try:
            getIndividual   = deartimeDB.exec_SQL('getIndividual', {'USER_ID': getCompanyObj.deartime_payerid}, 'fetchone')
            getReferralCode = deartimeDB.exec_SQL('getReferralCode', {'INDIVIDUAL_ID': getIndividual['dset'][0]}, 'fetchone')
            getReferralCodeFromIndividual = deartimeDB.exec_SQL('getReferralCodeIndividual', {'USER_ID': getCompanyObj.deartime_payerid}, 'fetchone')
            
            if not getReferralCode['dset']:
                referral_code = 'C' + get_random_string(length=9)
                dataDict = (referral_code,getIndividual['dset'][0],str(datetime.datetime.now()),str(datetime.datetime.now()))
                insertReferralCode = deartimeDB.exec_SQL('insertReferralCode',dataDict,'insert')
                data = {'REFERRAL_CODE':referral_code, 'INDIVIDUAL_ID': getIndividual['dset'][0] }
                updateReferralCode = deartimeDB.exec_SQL('updateReferralCode',data,'update')
                if 'error' in insertReferralCode or 'error' in updateReferralCode:
                    logger.error("Error in inserting or updating referral code")
            else:
                referral_code = getReferralCode['dset'][0]
            
            #check if individuals table referral code column is inserted
            if not getReferralCodeFromIndividual['dset']:
                data = {'REFERRAL_CODE':referral_code, 'INDIVIDUAL_ID': getIndividual['dset'][0] }
                updateReferralCode = deartimeDB.exec_SQL('updateReferralCode',data,'update')
                if 'error' in updateReferralCode:
                    logger.error('Error updating referral code')
                    
            return referral_code
        except Exception as ex:
            logger.error(str(ex))
    
    def style_eyes(self, img):
        img_size = img.size[0]
        eye_size = 70 #default
        quiet_zone = 40 #default
        mask = Image.new('L', img.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle((40, 40, 110, 110), fill=255)
        draw.rounded_rectangle((img_size-110, 40, img_size-40, 110), fill=255)
        draw.rounded_rectangle((40, img_size-110, 110, img_size-40), fill=255)
        return mask
    
    def generateReferralCodeQR(self, company_name, referral_code):
        try:
            api_key = 'AIzaSyBY20dlNSWsBtKK5MB1rnnSZLs_-4aTq5c'
            domain = 'deartime.page.link'
            dl = DynamicLinks(api_key,domain)
            params = {
                "androidInfo": {
                    "androidPackageName": 'com.deartime',
                    # "androidFallbackLink": 'https://play.google.com/store/apps/details?id=com.deartime&hl=en&gl=US',
                },
                "iosInfo": {
                    "iosBundleId": 'com.deartime.com',
                    # "iosFallbackLink": 'https://apps.apple.com/my/app/deartime/id1623745306',
                    "iosAppStoreId": '1623745306'
                },
            }
            referralLink = dl.generate_dynamic_link("https://www.deartime.com?rid="+referral_code, True, params)

            fileDir = os.path.join(settings.MEDIA_ROOT, company_name)
            file_path = os.path.join(fileDir, f'{company_name}.png').replace("\\", "/")

            if not os.path.exists(file_path):
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)
                logoLink = settings.STATICFILES_DIRS[0].replace("\\","/") + '/portal/img/favicon.png'
                logo = Image.open(logoLink)

                #adjust logo size
                basewidth = 75
                wpercent = (basewidth/float(logo.size[0]))
                hsize = int((float(logo.size[1])*float(wpercent)))
                logo = logo.resize((basewidth,hsize),Image.ANTIALIAS)
                
                qrcode = qr.QRCode(version=5,error_correction=qr.constants.ERROR_CORRECT_L, box_size=10)
                qrcode.add_data(referralLink)
                qrcode.make(fit=True)
                qr_eye_image = Image.open(settings.STATICFILES_DIRS[0].replace("\\","/") + '/portal/img/qr_template.png')
                qr_image = qrcode.make_image(image_factory=StyledPilImage,embeded_image_path=logoLink,module_drawer=CircleModuleDrawer())
                mask = self.style_eyes(qr_image)
                final_image = Image.composite(qr_eye_image,qr_image,mask)
                final_image.save(fileDir+'/'+company_name+'.png')
                
            return referralLink
        except Exception as ex:
            logger.error(str(ex))
        
            logger.error(str(ex)) 

    def checkChangePaymentMode(self, getCompanyObj):
        try:
            current = datetime.datetime.today()
            getActiveMember = Member.objects.filter(corporate_id=getCompanyObj.id, paid=True, rejected=False, void=False, is_deleted=False)
            if getActiveMember:
                getChangePaymentMode = PaymentModeHistory.objects.filter(corporate_id=getCompanyObj.id, is_updated=False, is_void=False)
                if getChangePaymentMode:
                    latestChangePaymentMode = PaymentModeHistory.objects.filter(corporate_id=getCompanyObj.id, is_updated=False, is_void=False).order_by('-created_datetime').first()
                    if current >= datetime.datetime.strptime(str(getCompanyObj.payment_due_date), '%Y-%m-%d'):
                        getCompanyObj.payment_due_date = latestChangePaymentMode.new_payment_due_date
                        getCompanyObj.payment_mode = latestChangePaymentMode.new_payment_mode
                        getCompanyObj.updated_datetime = datetime.datetime.now()
                        getCompanyObj.save()
                        latestChangePaymentMode.is_updated = True
                        latestChangePaymentMode.save()
            else:
                getChangePaymentMode = PaymentModeHistory.objects.filter(corporate_id=getCompanyObj.id, is_updated=False, is_void=False)
                if getChangePaymentMode:
                    latestChangePaymentMode = PaymentModeHistory.objects.filter(corporate_id=getCompanyObj.id, is_updated=False, is_void=False).order_by('-created_datetime').first()
                    getCompanyObj.payment_due_date = latestChangePaymentMode.new_payment_due_date
                    getCompanyObj.payment_mode = latestChangePaymentMode.new_payment_mode
                    getCompanyObj.updated_datetime = datetime.datetime.now()
                    getCompanyObj.save()
                    latestChangePaymentMode.is_updated = True
                    latestChangePaymentMode.save()
        except Exception as ex:
            logger.error(str(ex)) 

    def render_to_pdf(self, getUserCorporateObj, companyName, invoiceNo, template_src, context_dict):
        template = get_template(template_src)
        html  = template.render(context_dict)
        path = companyName + "/Invoice"
        try:
            isExist = os.path.exists(settings.MEDIA_ROOT.replace("\\", "/") + "/" + path)
            if not isExist:
                os.mkdir(settings.MEDIA_ROOT.replace("\\", "/") + "/" + path)
            file = invoiceNo.replace("/", "_") + ".pdf"
            f = open(settings.MEDIA_ROOT.replace("\\", "/")+"/"+path+"/"+file, 'wb')
            pdf_status  = pisa.CreatePDF(html, dest=f)
            f.close()
        except (Exception,FileNotFoundError) as e:
            logger.error(str(e),extra={'username':getUserCorporateObj.user_id})
            return HttpResponse("No such file or directory.")
        
        if pdf_status.err:
            return HttpResponse('Some errors were encountered <pre>' + html + '</pre>')
        return path+"/"+file

    def generateInvoiceMonthlyPayment(self, getCompanyObj):
        # Save to Deartime DB
        deartimeDB  = DearTimeDbConn()
        isConnected = deartimeDB.connect()
        if not isConnected:
            logger.error(settings.CONNECTION_LOST_MESSAGE)
        else:
            getUserCorporateObj   = CorporateProfile.objects.get(id=getCompanyObj.id)
            getUserCorporateRefNo = deartimeDB.exec_SQL('getUserRefNo', {'USER_ID': getUserCorporateObj.deartime_payerid}, 'fetchone')
            generateInvoiceNo = 'N' + str(datetime.date.today().year) + str(datetime.date.today().month).zfill(2) + '/' + str(get_next_value(sequence_name="invoice")).zfill(5) + str(settings.INVOICE_GENERATION_REFERENCE)
            total         = 0
            true_total    = 0

            memberList = []
            selectedMember = {}
            memberObj = Member.objects.filter(corporate=getUserCorporateObj, paid=True, rejected=False, void=False, is_deleted=False)
            calculator = PremiumCalculator()
            for member in memberObj:
                getMember = Member.objects.get(id=member.id)
                #getMemberProductMapping = MemberProductMapping.objects.filter(member_id=getMember.id, is_terminated=False).exclude(deartime_coverageid__isnull=True)
                getMemberProductMapping = MemberProductMapping.objects.filter(member_id=getMember.id, is_terminated=False)
                #tentative_premium = calculator.calculate_changed_premium(getMember.deartime_memberid, getUserCorporateObj.id, 'total', getMemberProductMapping, deartimeDB)
                #true_premium = calculator.calculate_changed_premium(getMember.deartime_memberid, getUserCorporateObj.id, 'total', getMemberProductMapping, deartimeDB, True)
                getMember.tentative_premium = calculator.calculate_changed_premium(getMember.deartime_memberid, getUserCorporateObj.id, 'total', getMemberProductMapping, deartimeDB)
                getMember.true_premium = calculator.calculate_changed_premium(getMember.deartime_memberid, getUserCorporateObj.id, 'total', getMemberProductMapping, deartimeDB, True)
                getMember.generated_invoice = True
                getMember.save()
                total += getMember.tentative_premium
                true_total += getMember.true_premium
                memberList.append(getMember)
                selectedMember.update({ getMember.employment_no : getMember.id })

                new_message_queue = MessagingQueue(
                    email_address = getMember.email_address,
                    module        = 'GenerateContractView'
                )
                new_message_queue.save()

            totalPayables = "{:.2f}".format(total)
            totalPayablesWord = num2words(totalPayables, to='currency').title().replace('Euro', "")
            if float(totalPayables).is_integer():
                totalPayablesWord = totalPayablesWord.split(',')[0]
            totalPayablesWord += " Only"

            rowCount = 10
            paginator = Paginator(memberList, rowCount)

            corporate_user = CorporateUser.objects.get(id=getUserCorporateObj.user_id)

            saveInvoice = Invoice (
                company          = getUserCorporateObj,
                invoice_no       = generateInvoiceNo,
                total_amount     = totalPayables,
                created_by       = corporate_user,
                status           = 'Pending Payment'
            )
            saveInvoice.save()

            file = self.render_to_pdf(getUserCorporateObj, getUserCorporateObj.company_name, generateInvoiceNo, 'InvoiceAndPayment/Invoice.html',
                {
                    'pagesize'           : 'A4',
                    'image_url'          : settings.STATICFILES_DIRS[0].replace("\\","/") + '/portal/img/deartime-logo-inverted-color.png',
                    'company'            : getUserCorporateObj,
                    'tables'             : paginator,
                    'total_payables'     : totalPayables,
                    'total_payables_text': totalPayablesWord,
                    'payor_ref'          : getUserCorporateRefNo['dset'][0],
                    'invoice_no'         : generateInvoiceNo,
                    'invoice_date'       : datetime.datetime.strftime(Invoice.objects.get(company_id=getUserCorporateObj.id, invoice_no=generateInvoiceNo).created_datetime, '%d %B %Y'),
                    'flag'               : 'invoice'
                })

            for member in memberList:
                # getMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False)
                # tentative_premium = calculator.calculate_changed_premium(member.deartime_memberid, getUserCorporateObj.id, 'total', getMemberProductMapping, deartimeDB)
                # true_premium = calculator.calculate_changed_premium(member.deartime_memberid, getUserCorporateObj.id, 'total', getMemberProductMapping, deartimeDB, True)
                generateOrderNo = 'ORD' + str(datetime.date.today().year) + str(datetime.date.today().month) + '/' + str(get_next_value(sequence_name=getUserCorporateObj.company_name+"_order/")).zfill(5)
                saveOrder = Order(
                    invoice    = saveInvoice,
                    member     = member,
                    order_no   = generateOrderNo,
                    amount     = member.tentative_premium,
                    true_amount= member.true_premium,
                    created_by = corporate_user
                )
                saveOrder.save()

                getLatestOrderID        = deartimeDB.exec_SQL('selectMaxIDOrder', {}, 'fetchone')
                getLatestTransactionID  = deartimeDB.exec_SQL('selectMaxIDTransaction', {}, 'fetchone')
                nextLatestOrderID       = getLatestOrderID['dset'][0] + 1
                nextLatestTransactionID = getLatestTransactionID['dset'][0] + 1
                orderRefNo              = 'OR' + str(nextLatestOrderID).zfill(6)
                transactionRefNo        = 'TX' + str(nextLatestTransactionID).zfill(6)
                nextTryOn               = datetime.datetime.now() + datetime.timedelta(days=7)
                dataDictsOR             = (str(uuid.uuid4()), totalPayables, true_total, getUserCorporateObj.deartime_payerid, str(nextTryOn), str(datetime.datetime.now()), str(datetime.datetime.now()), 0, orderRefNo, str(datetime.datetime.now()), str(datetime.datetime.now()))
                getNewOrderID           = deartimeDB.exec_SQL('insertOrder', dataDictsOR, 'insert')
                dataDictsTR             = (str(uuid.uuid4()), getNewOrderID['lastID'], 'manual', 'TRX'+(str(time())).split(".")[0], totalPayables, transactionRefNo, str(datetime.datetime.now()), str(datetime.datetime.now()), str(datetime.datetime.now()), 'FPX-B2B', getUserCorporateObj.company_name)
                getNewTransactionID     = deartimeDB.exec_SQL('insertTransaction', dataDictsTR, 'insert')
                for mem in memberList:
                    getIndividual       = deartimeDB.exec_SQL('getIndividual', {'USER_ID': mem.deartime_memberid}, 'fetchone')
                    getUnpaidCoverage   = deartimeDB.exec_SQL('getUnpaidCoverage', {'OWNER_ID': getIndividual['dset'][0], 'PAYER_ID': getUserCorporateObj.deartime_payerid}, 'fetchall')
                    for coverid in getUnpaidCoverage['dset']:
                        dataDictsCO         = (coverid[0], getNewOrderID['lastID'], str(datetime.datetime.now()), str(datetime.datetime.now()))
                        getNewCoverageOrderID = deartimeDB.exec_SQL('insertCoverageOrder', dataDictsCO, 'insert')
                        dataDictsCoverages  = {'CSD_INVOICE_DATE': str(datetime.datetime.now()), 'UPDATED_DATE':str(datetime.datetime.now()), 'COVERAGE_ID': coverid[0]}
                        updateCoveragesCSD  = deartimeDB.exec_SQL('updateCoveragesCSD', dataDictsCoverages, 'update')
                saveInvoice.deartime_orderid = getNewOrderID['lastID']
                saveInvoice.save()

            for mem2 in memberList:
                mem2.status = 'P.Invoice'
                mem2.save()

            strToHash  = settings.PROD_SENANGPAY_SECRET_KEY + saveInvoice.invoice_no.replace("/", "-") + str(saveInvoice.total_amount) + saveInvoice.invoice_no.replace("/", "-")
            sha256hash = hmac.new(bytes(settings.PROD_SENANGPAY_SECRET_KEY, 'UTF-8'), bytes(strToHash, 'UTF-8'), hashlib.sha256)
            saveInvoice.hash_value = sha256hash.hexdigest()
            saveInvoice.save()

            deartimeDB.close()

    def currentDateTesting(self, corporateID, today=None):
        if settings.ENVIRONMENT_INDICATOR != '':
            preferredCurrentDate = CurrentDate.objects.filter(corporate_id=corporateID)
            if preferredCurrentDate:
                currentObject = CurrentDate.objects.get(corporate_id=corporateID)
                current = currentObject.current_datetime
            else:
                if today:
                    current = datetime.datetime.today()
                else:
                    current = datetime.datetime.now()
        else:
            if today:
                current = datetime.datetime.today()
            else:
                current = datetime.datetime.now()
        return current
    
    def get_timestamp(self, filename):
        return filename.split("_")[-3].split('.')[0]+filename.split("_")[-2].split('.')[0]+filename.split("_")[-1].split('.')[0]
    
    def round_half_up(self, n, decimals=0):
        multiplier = 10 ** decimals
        return math.floor(n * multiplier + 0.5) / multiplier
    
    def code_randomiser(self):
        current_time = datetime.datetime.now()
        random_code = current_time.strftime("%Y%m%d_%H%M%S_")
        return f"_{random_code}"
class DearTimeDbConn():

    def connect(self):
        username = settings.DT_USERNAME_DB
        password = settings.DT_PASSWORD_DB
        host     = settings.DT_HOST_DB
        port     = settings.DT_PORT_DB
        DB_NAME  = settings.DT_DATABASE_NAME_DB
        self.isConnected = True
        try:
            self.mydb = mysql.connector.connect(
                host     = host,
                user     = username,
                password = password,
                database = DB_NAME
            )
            self.mycursor = self.mydb.cursor()
            self.init_SQL()
        except Exception as e:
            logger.error(str(e))
            self.isConnected = False
        return self.isConnected

    def close(self):
        self.mycursor.close()

    def init_SQL(self):
        self.dSql = {}

        # Select
        self.dSql['selectMaxIDUserTB']      = """SELECT MAX(id) FROM users"""
        self.dSql['getProductObj']          = """SELECT id FROM products WHERE name = '{PRD_NAME}'"""
        self.dSql['getCoverageUpdateTime']  = """SELECT updated_at FROM coverages WHERE owner_id = '{INDIVIDUAL_ID}' AND id = '{COVERAGE_ID}'"""
        self.dSql['getCoverages']           = """SELECT owner_id, payer_id, covered_id, product_id, product_name, state, payment_term, coverage, deductible, max_coverage, payment_monthly, payment_annually, has_loading, color, is_accepted_by_owner, parent_id, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND status = 'terminate' ORDER BY id DESC LIMIT 5"""
        #self.dSql['getCoveragesDates']      = """SELECT owner_id, payer_id, covered_id, payment_monthly, payment_annually, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND state = 'active' ORDER BY id DESC LIMIT 0, 1"""
        self.dSql['getCoveragesDatesProduct'] = """SELECT owner_id, payer_id, covered_id, payment_monthly, payment_annually, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_name='{PRODUCT_NAME}' AND state = 'active' ORDER BY id DESC LIMIT 0, 1"""
        self.dSql['getCoverageNDD']         = """SELECT owner_id, payer_id, covered_id, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date, payor_first_product_purchase_date, payor_next_payment_date, payor_last_payment_on FROM coverages WHERE payer_id = '{PAYER_ID}' AND last_payment_on is not NULL ORDER BY id DESC LIMIT 0, 1"""
        # self.dSql['getCoveragesDates']      = """SELECT owner_id, payer_id, covered_id, payment_monthly, payment_annually, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND state = 'active'"""
        self.dSql['getProductCoveragesDates'] = """SELECT owner_id, payer_id, covered_id, payment_monthly, payment_annually, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND state = 'active' AND product_name = '{PRODUCT_NAME}'"""
        self.dSql['selectMaxIDCoverages']   = """SELECT MAX(id) FROM coverages"""
        self.dSql['getCoveragesDates']      = """SELECT owner_id, payer_id, covered_id, payment_monthly, payment_annually, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND state = 'active' ORDER BY id ASC LIMIT 0, 1"""
        self.dSql['getCoveragesDatesv2']    = """SELECT owner_id, payer_id, covered_id, payment_monthly, payment_annually, first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_name = '{PRODUCT_NAME}' AND status = 'fulfilled' ORDER BY id ASC LIMIT 0, 1"""
        self.dSql['states']                 = """SELECT display_name FROM states"""
        self.dSql['cities']                 = """SELECT cities.display_name, states.display_name FROM cities INNER JOIN states ON cities.state_id=states.id"""
        self.dSql['postal_codes']           = """SELECT postal_codes.display_name, cities.display_name FROM postal_codes INNER JOIN cities ON postal_codes.city_id=cities.id"""
        self.dSql['validateCoverage']       = """SELECT coverages.id, coverages.coverage, coverages.product_name, coverages.status FROM coverages LEFT JOIN individuals ON coverages.owner_id=individuals.id WHERE coverages.state = 'active' and individuals.user_id = '{USER_ID}' and coverages.product_name = '{PRODUCT_NAME}'"""
        self.dSql['validateRenewalCoverage'] = """SELECT coverages.id, coverages.coverage, coverages.product_name, coverages.status FROM coverages LEFT JOIN individuals ON coverages.owner_id=individuals.id WHERE coverages.state = 'active' and individuals.user_id = '{USER_ID}' and coverages.payer_id = '{PAYER_ID}' and coverages.product_name = '{PRODUCT_NAME}'"""
        self.dSql['validateMedicalCoverage']= """SELECT id FROM coverages WHERE owner_id = '{INDIVIDUAL_ID}' AND product_id = '{MEDICAL_PRD_ID}' AND status='active'"""
        self.dSql['underwritingStatus']     = """SELECT uw.death, uw.disability, uw.ci, uw.medical FROM underwritings as uw LEFT JOIN individuals ind ON uw.individual_id = ind.id LEFT JOIN users us ON ind.user_id = us.id WHERE ind.id = '{USER_ID}' ORDER BY uw.id DESC LIMIT 0, 1"""
        self.dSql['validateMember']         = """SELECT usr.id, usr.password FROM individuals as ind LEFT JOIN users usr on ind.user_id = usr.id WHERE ind.mobile = '{MOBILE}' AND usr.email='{EMAIL}' AND ind.nric='{NRIC}'"""
        self.dSql['getProductCoverage']     = """SELECT coverage, product_name, payment_monthly, payment_annually FROM coverages WHERE owner_id = '{OWNER_ID}' and payer_id = '{PAYER_ID}' and product_id = '{PRD_ID}' AND id ='{COVERAGE_ID}' AND (status = 'unpaid' or status = 'decrease-unpaid' or status = 'increase-unpaid')"""
        self.dSql['getProductLIKE']         = """SELECT id FROM products WHERE name LIKE '{PRD_NAME}'"""
        self.dSql['getUserOS']              = """SELECT os, token FROM user_notification_tokens WHERE user_id LIKE '{USER_ID}' ORDER BY id DESC LIMIT 1"""
        self.dSql['getMedicalPlans']        = """SELECT options FROM products WHERE name = 'Medical'"""
        self.dSql['selectMaxIDOrder']       = """SELECT MAX(id) FROM orders"""
        self.dSql['selectMaxIDTransaction'] = """SELECT MAX(id) FROM transactions"""
        self.dSql['getCoverageID']          = """SELECT id FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_id = '{PRD_ID}'"""
        self.dSql['getCoveragePaymentDates']= """SELECT first_payment_on, next_payment_on, last_payment_on, ndd_payment_due_date FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_name = '{PRODUCT_NAME}' AND state = 'active'"""
        self.dSql['getMemCoverageID']       = """SELECT id FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_id = '{PRD_ID}' AND status != 'terminate'"""
        self.dSql['getUnpaidCoverage']      = """SELECT id FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND (status = 'unpaid' or status = 'decrease-unpaid' or status = 'increase-unpaid' or status = 'grace-unpaid' or status ='grace-increase-unpaid')"""
        self.dSql['getGraceCoverage']       = """SELECT id FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND (status = 'active' or status = 'active-increased' or status = 'grace-unpaid' or status ='grace-increase-unpaid')"""
        self.dSql['getCoverageStatus']      = """SELECT status FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}'"""
        self.dSql['getCoverageUuid']        = """SELECT uuid FROM coverages WHERE id = '{COVERAGE_ID}'"""
        self.dSql['getIndividual']          = """SELECT id FROM individuals WHERE user_id = '{USER_ID}'"""
        self.dSql['getIndividualNRIC']      = """SELECT id FROM individuals WHERE nric = '{NRIC}'"""
        self.dSql['selectMaxIDActions']     = """SELECT MAX(id) FROM actions"""
        self.dSql['getOrderStatus']         = """SELECT status FROM orders WHERE id ='{DEARTIME_ORDERID}'"""
        self.dSql['getCoverageFromOrder']   = """SELECT coverages.id, coverages.product_name FROM coverages INNER JOIN coverage_orders ON coverages.id=coverage_orders.coverage_id AND coverage_orders.order_id = '{ORDER_ID}' AND coverages.owner_id = '{INDIVIDUAL_ID}'"""
        self.dSql['getCoverageFromMPM']   = """SELECT coverages.id, coverages.product_name FROM coverages WHERE id = '{COVERAGE_ID}'"""
        self.dSql['getIndividualFromCoverage'] = """SELECT individuals.user_id FROM individuals INNER JOIN coverages ON coverages.owner_id = individuals.id AND coverages.id = '{COVERAGE_ID}'"""
        self.dSql['getIndividualUuid']      = """SELECT uuid FROM individuals WHERE user_id = '{USER_ID}'"""
        self.dSql['getUserUuid']            = """SELECT uuid FROM users WHERE id = '{USER_ID}'"""
        self.dSql['getInvoicePaidDatetime'] = """SELECT updated_at FROM orders WHERE id = '{ORDER_ID}'"""
        self.dSql['getCoverageCount']       = """SELECT COUNT(DISTINCT product_name) FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}'"""
        self.dSql['getCoverageAcceptedCount'] = """SELECT COUNT(corporate_user_status) FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND corporate_user_status='Accepted'"""
        self.dSql['getMedicalCoverage']     = """SELECT deductible, product_name, payment_monthly, payment_annually FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_id = '{MEDICAL_PRD_ID}' AND (status = 'unpaid' or status = 'decrease-unpaid' or status = 'increase-unpaid')"""
        self.dSql['getPremiumRate']         = """SELECT options FROM products where name = '{PRODUCT_NAME}'"""
        self.dSql['getJob']                 = """SELECT occ FROM individuals WHERE user_id = '{DEARTIME_MEMBERID}'"""
        self.dSql['getLoading']             = """SELECT death, TPD, Medical, Accident FROM industry_jobs WHERE id = '{JOB_ID}'"""
        self.dSql['getUserRefNo']           = """SELECT ref_no FROM users WHERE id = '{USER_ID}'"""
        self.dSql['getThanksGiving']        = """SELECT percentage FROM thanksgivings WHERE individual_id = '{INDIVIDUAL_ID}' and type = 'self'"""
        self.dSql['getIndividualData']      = """SELECT nric, dob, gender FROM individuals WHERE user_id = '{USER_ID}'"""
        self.dSql['getIndividualDataNRIC']      = """SELECT nric, dob, gender, user_id FROM individuals WHERE nric = '{NRIC}'"""
        self.dSql['getProdCoverageStatus']  = """SELECT status,deductible FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_id = '{PRD_ID}' AND id ='{COVERAGE_ID}'"""
        self.dSql['getUnderwriting']        = """SELECT MAX(id) FROM underwritings WHERE individual_id = '{INDIVIDUAL_ID}'"""
        self.dSql['getSponsoredInsurance']  = """SELECT i.name, c.next_payment_on FROM spo_charity_fund_application s LEFT JOIN individuals i ON i.user_id = s.user_id LEFT JOIN coverages c ON c.owner_id=i.id WHERE s.user_id = '{USER_ID}' AND s.status='Active' AND s.active = 1 AND c.status='Active'"""
        self.dSql['getSponsoredInsuranceWaitingList']  = """SELECT id FROM spo_charity_fund_application WHERE user_id = '{USER_ID}' AND (status='Pending' OR status='Submitted' OR status='Queue') AND active = 1"""
        self.dSql['getCoverageRejectedCount']          = """SELECT COUNT(status) FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND (status='terminate' OR status='decrease-terminate' OR status='increase-terminate') AND id NOT IN ({COVERAGE_ID})"""
        self.dSql['validateExistingEmailMobile']       = """SELECT usr.id FROM individuals as ind LEFT JOIN users usr on ind.user_id = usr.id WHERE ind.mobile = '{MOBILE}' OR usr.email='{EMAIL}' OR ind.nric='{NRIC}'"""
        self.dSql['validateFailedMedicalSurvey']       = """SELECT individual_id FROM underwritings WHERE death = 0 AND disability = 0 AND ci = 0 AND medical = 0 AND individual_id = '{ID}' ORDER BY created_at DESC"""
        self.dSql['validatePassedMedicalSurvey']       = """SELECT individual_id FROM underwritings WHERE death = 1 AND disability = 1 AND ci = 1 AND medical = 1 AND individual_id = '{ID}' ORDER BY created_at DESC"""
        self.dSql['checkLatestCoveragesData']          = """SELECT * FROM ( SELECT created_at, COUNT(created_at) FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND status = 'terminate' GROUP BY created_at ORDER BY created_at DESC) x LIMIT 1;"""
        self.dSql['getLatestTerminateCovData']         = """SELECT coverage, payment_annually, payer_id, parent_id, product_id, max_coverage, product_name, payment_monthly, covered_id, owner_id, payment_term, status, state, created_at, updated_at, deductible, ndd_payment_due_date, has_loading, color FROM coverages WHERE created_at = '{CREATED_AT}';"""
        self.dSql['validateBankAccount'] = """SELECT owner_id, account_no, bank_name FROM bank_accounts WHERE owner_id = '{OWNER_ID}'"""
        self.dSql['getProspectDetails']                = """SELECT name, nric, dob, gender FROM individuals WHERE user_id = '{USER_ID}'"""
        self.dSql['getThanksgivingsSelfType']          = """SELECT id, percentage FROM thanksgivings WHERE individual_id = '{INDIVIDUAL_ID}' AND type = 'self' AND deleted_at IS NULL"""
        self.dSql['getThanksgivingsCharityType']       = """SELECT id, percentage FROM thanksgivings WHERE individual_id = '{INDIVIDUAL_ID}' AND type = 'charity' AND deleted_at IS NULL"""
        self.dSql['selectMaxIDCredits']     = """SELECT MAX(id) FROM credits"""
        self.dSql['getVerifiedEKYC']        = """SELECT status FROM customer_verifications WHERE individual_id='{INDIVIDUAL_ID}'"""
        self.dSql['getReferralCode']        = """SELECT referralcode FROM referralcode WHERE individual_id = '{INDIVIDUAL_ID}'"""
        self.dSql['getReferral']       = """SELECT to_referee_name,created_at,thanksgiving_percentage FROM referral WHERE from_referrer = '{USER_ID}'"""
        self.dSql['getPayment']       = """SELECT month,transaction_ref,amount,year,transaction_date,to_referee_name FROM referral WHERE from_referrer = '{USER_ID}' AND payment_status='PAID'"""
        self.dSql['getReferralCodeIndividual']       = """SELECT referral_code FROM individuals WHERE user_id = '{USER_ID}'"""
        self.dSql['getTerminateCoverage']= """SELECT * FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_id = '{PRODUCT_ID}' AND status != 'terminate'"""
        self.dSql['getReferrerFromUser'] = """SELECT from_referrer_name, from_referrer FROM users WHERE id =  '{USER_ID}'"""
        self.dSql['getReferralThanksGiving']        = """SELECT percentage FROM thanksgivings WHERE individual_id = '{INDIVIDUAL_ID}' and type = 'promoter'"""
        self.dSql['getUnderwritingProductEligibility']  = """SELECT id, title, parent_uws_id, accident, critical_illiness, medical, disability, death FROM uws WHERE id = '{UW_ID}' AND group_id IN ({GROUP_ID})"""
        self.dSql['getUnderwritingProductLoading']  = """SELECT percentage FROM uws_loading ul LEFT JOIN products p ON p.id = ul.product_id WHERE ul.uws_id = '{UW_ID}' AND p.name = '{PRODUCT_NAME}'"""
        self.dSql['getDigestiveSystemTitle']  = """SELECT id, title, parent_uws_id FROM uws WHERE id IN ({DIGESTIVE_ID}) AND parent_uws_id = (SELECT id FROM uws WHERE title = 'Digestive System')"""
        self.dSql['getUnderwritingAnswer']         = """SELECT sio_answers FROM underwritings WHERE individual_id = '{INDIVIDUAL_ID}' ORDER BY created_at DESC"""
        self.dSql['getUnderwritingAnswerRenewal']  = """SELECT u.sio_answers FROM underwritings u LEFT JOIN coverages c ON u.individual_id = c.owner_id AND c.uw_id = u.id WHERE u.individual_id = '{INDIVIDUAL_ID}' AND c.status != 'terminate' AND c.payer_id = '{PAYER_ID}' ORDER BY c.created_at DESC"""
        self.dSql['getDigestiveID']                    = """SELECT id FROM uws WHERE title = 'Digestive System'"""
        self.dSql['validateMedicalSurvey'] = """SELECT death, disability, ci, medical FROM underwritings WHERE individual_id = '{ID}' ORDER BY created_at DESC LIMIT 0, 1"""
        self.dSql['getMedicalSurveyCreatedDatetime'] = """SELECT created_at FROM underwritings WHERE individual_id = '{ID}' ORDER BY created_at DESC LIMIT 0, 1"""
        self.dSql['getThanksgivingCoverageID'] = """SELECT id FROM coverages WHERE owner_id = '{INDIVIDUAL_ID}' and status = 'active'"""
        self.dSql['getOrdersRetries'] = """SELECT retries FROM orders WHERE id = '{ORDER_ID}'"""
        self.dSql['getOrdersDetails'] = """SELECT retries, true_amount, id FROM orders WHERE id = '{ORDER_ID}'"""
        self.dSql['getTransactDetails'] = """SELECT id FROM transactions WHERE order_id = '{ORDER_ID}'"""
        # queries for calling the campaign code 
        self.dSql['getCampaignCode'] = """SELECT COALESCE(NULLIF(campaign_code, ''), NULL) FROM voucher_campaign_list LEFT JOIN  voucher_code ON voucher_campaign_list.id = voucher_code.campaign_id LEFT JOIN voucher_details on voucher_details.voucher_code = voucher_code.voucher_code where nric = '{USER_IC}'"""
        self.dSql['getCampaignList'] = """SELECT campaign_code FROM voucher_campaign_list"""
        # not complete for the results
        self.dSql['getVoucherMembers'] = """select voucher_details.nric, voucher_details.name, users.email, voucher_campaign_list.campaign_code, individuals.mobile, individuals.nationality, individuals.dob, individuals.gender, users.promoter_id, users.id from individuals join voucher_details on individuals.nric = voucher_details.nric join users on individuals.user_id = users.id join voucher_code on voucher_code.voucher_code = voucher_details.voucher_code join voucher_campaign_list on voucher_campaign_list.id = voucher_code.campaign_id where promoter_id = '{PAYER_ID}' """
        self.dSql['getPackageInfo']    = """select vapor.individuals.nric, vapor.voucher_code.voucher_code, vapor.voucher_campaign_list.campaign_code from vapor.coverages join vapor.individuals on vapor.coverages.owner_id = vapor.individuals.id join vapor.voucher_details on vapor.individuals.nric =  vapor.voucher_details.nric join vapor.voucher_code on vapor.voucher_code.voucher_code = voucher_details.voucher_code join vapor.voucher_campaign_list on vapor.voucher_code.campaign_id = vapor.voucher_campaign_list.id where corporate_user_status = 'accepted' and campaign_records = 1 and individuals.nric = '{USER_NRIC}' and campaign_code = '{CAMPAIGN}' """
        self.dSql['getAdditionCoverage']    = """select vapor.coverages.product_name, vapor.coverages.coverage from vapor.coverages join vapor.individuals on vapor.coverages.owner_id = vapor.individuals.id join vapor.voucher_details on vapor.individuals.nric =  vapor.voucher_details.nric join vapor.voucher_code on vapor.voucher_code.voucher_code = voucher_details.voucher_code join vapor.voucher_campaign_list on vapor.voucher_code.campaign_id = vapor.voucher_campaign_list.id where corporate_user_status = 'accepted' and campaign_records = 1 and individuals.nric = '{USER_NRIC}' and campaign_code = '{CAMPAIGN}' """

        
        # Insert
        self.dSql['insertUser']             = """INSERT INTO users(ref_no, uuid, type, corporate_type, email, password, activation_token, active, created_at, updated_at, promoter_id) VALUES
                                              (%s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s)"""
        self.dSql['insertCorpUser']         = """INSERT INTO users(ref_no, uuid, type, corporate_type, email, password, activation_token, active, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertIndividual']       = """INSERT INTO individuals(uuid, user_id, name) VALUES
                                              (%s, %s, %s)"""
        self.dSql['insertCoverages']        = """INSERT INTO coverages(ref_no, coverage, payment_annually, payer_id, parent_id, uuid, product_id, max_coverage, product_name, payment_monthly, covered_id, owner_id, payment_term, payment_term_new, status, state, created_at, updated_at, deductible, ndd_payment_due_date, has_loading, color) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'inactive', %s, %s, %s, %s, %s, %s)"""
        self.dSql['reinsertCoverages']      = """INSERT INTO coverages(ref_no, uuid, owner_id, payer_id, covered_id, product_id, product_name, status, state, payment_term, coverage, deductible, max_coverage, payment_monthly, payment_annually, has_loading, color, is_accepted_by_owner, parent_id, created_at, updated_at, ndd_payment_due_date) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, 'unpaid', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertIndividualMember'] = """INSERT INTO individuals(uuid, user_id, name, nric, mobile, gender, dob, nationality, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertOrder']            = """INSERT INTO orders(uuid, amount, true_amount, payer_id, next_try_on, last_try_on, due_date, parent_id, ref_no, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertOrderRenewal']     = """INSERT INTO orders(uuid, amount, true_amount, payer_id, type, next_try_on, last_try_on, due_date, parent_id, ref_no, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s, 'renew', %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertTransaction']      = """INSERT INTO transactions(uuid, order_id, gateway, transaction_ref, amount, ref_no, created_at, updated_at, date, card_type, card_no) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertCoverageOrder']    = """INSERT INTO coverage_orders(coverage_id, order_id, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s)"""
        self.dSql['insertActions']          = """INSERT INTO actions(uuid, ref_no, user_id, type, event, actions, status, execute_on, createdbyable_type, createdbyable_id, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertActionCoverage']   = """INSERT INTO action_coverage(action_id, coverage_id, created_at, updated_at) VALUES
                                              (%s, %s, %s, %s)"""
        self.dSql['insertNotification']     = """INSERT INTO notifications(uuid, user_id, title, text, full_text, data, is_read, auto_read, `show`, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertCredits']          = """INSERT INTO credits(uuid, ref_no, order_id, user_id, from_id, amount, type, type_item_id, created_at, updated_at) VALUES 
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertBankAccount']      = """INSERT INTO bank_accounts(uuid, owner_id,owner_type,account_no,bank_name,verified_on,verified_by,created_at,updated_at,deleted_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertReferralCode']     = """INSERT INTO referralcode(referralcode, individual_id,created_at,updated_at) VALUES (%s, %s, %s, %s)"""
        self.dSql['insertReferral']         = """INSERT INTO referral(from_referrer, to_referee, from_referral_name, to_referee_name, amount, thanksgiving_percentage, payment_status, order_id, month, year, transaction_date, created_at, updated_at, uuid) VALUES 
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        self.dSql['insertSpoCharityFunds']  = """INSERT INTO spo_charity_funds(uuid, user_id, order_id, transaction_id, amount, percentage, charity_fund, created_at, updated_at, status) VALUES
                                              (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'ON HOLD')"""
        self.dSql['insertCoverThanksgive']     = """INSERT INTO coverage_thanksgivings(coverage_id, thanksgiving_id) VALUES (%s, %s)"""
        
        # Update
        self.dSql['updateIndividualMember']              = """UPDATE individuals SET name='{NAME}', nric='{NRIC}', mobile='{MOBILE}', gender='{GENDER}', dob='{DOB}', nationality='{NATIONALITY}' WHERE user_id = '{DEARTIME_MEMBERID}'"""
        self.dSql['updateMemberEmail']                   = """UPDATE users SET email='{EMAIL}' WHERE id = '{DEARTIME_MEMBERID}'"""
        self.dSql['updateCoverages']                     = """UPDATE coverages SET coverage='{COVERAGE}' WHERE owner_id = '{INDIVIDUAL_ID}' AND product_id = '{PRD_ID}'"""
        self.dSql['UpdateNewPaymentTerm']                = """UPDATE coverages SET payment_term_new ='{NEW_PAYMENT_TERM}' WHERE payer_id='{CORPORATE_ID}' and status != 'fulfilled'"""
        self.dSql['UpdatePaymentTerm']                   = """UPDATE coverages SET payment_term ='{PAYMENT_TERM}' WHERE owner_id='{OWNER_ID}'"""
        self.dSql['updateMedicalCoverage']               = """UPDATE coverages SET coverage='{PLAN}', deductible='{COVERAGE}' WHERE owner_id = '{INDIVIDUAL_ID}' AND product_id = '{PRD_ID}'"""
        self.dSql['updateOrders']                        = """UPDATE orders SET status='successful', updated_at='{UPDATED_DATE}' WHERE id = '{DEARTIME_ORDERID}'"""
        self.dSql['updateTransactions']                  = """UPDATE transactions SET success='1', updated_at='{UPDATED_DATE}', transaction_id='{TRANSACTION_REF}' WHERE order_id = '{DEARTIME_ORDERID}'"""
        #self.dSql['updateCoveragesStatus']               = """UPDATE coverages SET status='{NEW_STATUS}', state='active', first_payment_on='{UPDATED_DATE}', next_payment_on='{PAYMENT_DUEDATE}', last_payment_on='{UPDATED_DATE}', updated_at='{UPDATED_DATE}', uw_id='{UW_ID}' WHERE id = '{COVERAGE_ID}' AND (status = '{ORIGINAL_STATUS}')"""
        self.dSql['updateCoveragesStatus']               = """UPDATE coverages SET status='{NEW_STATUS}', state='active', first_payment_on='{FIRST_PAYMENT_ON}', next_payment_on='{NEXT_PAYMENT_ON}', last_payment_on='{LAST_PAYMENT_ON}', payor_first_product_purchase_date ='{FIRST_PAYMENT_ON}', payor_next_payment_date ='{PAYOR_NEXT_PAYMENT_DATE}', payor_last_payment_on='{INVOICE_CREATED_DATE}', updated_at='{UPDATED_DATE}', uw_id='{UW_ID}' WHERE id = '{COVERAGE_ID}' AND (status = '{ORIGINAL_STATUS}')"""
        self.dSql['updateRenewalCoveragesStatus']        = """UPDATE coverages SET status='{NEW_STATUS}', state='active', first_payment_on='{FIRST_PAYMENT_DATE}', next_payment_on='{PAYMENT_DUEDATE}', last_payment_on='{INVOICE_CREATED_DATE}', payor_first_product_purchase_date ='{FIRST_PAYMENT_DATE}', payor_next_payment_date ='{PAYOR_NEXT_PAYMENT_DATE}', payor_last_payment_on='{INVOICE_CREATED_DATE}', updated_at='{UPDATED_DATE}', uw_id='{UW_ID}' WHERE id = '{COVERAGE_ID}' AND (status = '{ORIGINAL_STATUS}')"""
        # self.dSql['updateRenewalCoveragesStatusV2']        = """UPDATE coverages SET status='{NEW_STATUS}', state='active', first_payment_on='{FIRST_PAYMENT_DATE}', next_payment_on='{PAYMENT_DUEDATE}', last_payment_on='{INVOICE_CREATED_DATE}', payor_first_product_purchase_date ='{FIRST_PAYMENT_DATE}', payor_next_payment_date ='{PAYOR_NEXT_PAYMENT_DATE}', payor_last_payment_on='{INVOICE_CREATED_DATE}', updated_at='{UPDATED_DATE}', uw_id='{UW_ID}' WHERE id = '{COVERAGE_ID}' AND (status = '{ORIGINAL_STATUS}')"""
        self.dSql['updateCoveragesFulfilled']            = """UPDATE coverages SET status='{NEW_STATUS}', state='inactive' WHERE id = '{COVERAGE_ID}' AND (status = '{ORIGINAL_STATUS}')"""
        self.dSql['updateCoveragesCSD']                  = """UPDATE coverages SET csd_corporate_invoice_date='{CSD_INVOICE_DATE}', updated_at='{UPDATED_DATE}' WHERE id='{COVERAGE_ID}' AND (STATUS='unpaid' OR STATUS='decrease-unpaid' OR STATUS='increase-unpaid' OR STATUS='grace-unpaid' OR STATUS ='grace-increase-unpaid')"""
        self.dSql['updateCoveragesNDD']                  = """UPDATE coverages SET payor_next_payment_date = '{NDD_PAYMENT_DUE_DATE}', ndd_payment_due_date ='{NDD_PAYMENT_DUE_DATE}', updated_at='{UPDATED_DATE}' WHERE payer_id='{PAYER_ID}' """
        self.dSql['updateMemberCoverageNDD']             = """UPDATE coverages SET ndd_payment_due_date='{NDD_PAYMENT_DUE_DATE}', updated_at='{UPDATED_DATE}' WHERE id='{COVERAGE_ID}' AND (STATUS='unpaid' OR STATUS='decrease-unpaid' OR STATUS='increase-unpaid' OR STATUS='grace-unpaid' OR STATUS ='grace-increase-unpaid')"""
        self.dSql['updateCoveragesPayment']              = """UPDATE coverages SET payment_monthly='{PAYMENT_MONTHLY}', payment_annually='{PAYMENT_ANNUALLY}', full_premium='{FULL_PREMIUM}' WHERE id = '{COVERAGE_ID}'"""
        self.dSql['updateTerminateCoverage']             = """UPDATE coverages SET status = 'terminate' WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}'"""
        self.dSql['updateSingleTerminateCoverage']       = """UPDATE coverages SET status = 'terminate' WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}' AND product_id = '{PRODUCT_ID}'"""
        self.dSql['updateCovMpmTerminate']               = """UPDATE coverages SET status = 'terminate' WHERE id = '{DEARTIME_COVERAGE_ID}'"""
        self.dSql['updateCancelledCoverage']             = """UPDATE coverages SET status = 'cancelled' WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}'"""
        self.dSql['updateSponsoredInsuranceConfirm']     = """UPDATE spo_charity_fund_application SET Corporate_SPO_confirm = 1 WHERE user_id = '{USER_ID}'"""

        self.dSql['updateUnterminateCoverage']           = """UPDATE coverages SET status = 'unpaid', state = 'inactive' WHERE owner_id = {OWNER_ID} AND payer_id = '{PAYER_ID}'"""
        self.dSql['updateBankAccount']                   = """ UPDATE bank_accounts SET account_no='{ACC_NO}', bank_name='{BANK_NAME}', updated_at='{UPDATE_DATETIME}' where owner_id='{OWNER_ID}'"""
        self.dSql['updateCoverageDate']                  = """UPDATE coverages SET created_at = '{UPDATED_DATE}', updated_at='{UPDATED_DATE}', status='unpaid' WHERE id='{COVERAGE_ID}'"""
        self.dSql['updateCoverageDateWithoutStatus']     = """UPDATE coverages SET created_at = '{UPDATED_DATE}', updated_at='{UPDATED_DATE}' WHERE id='{COVERAGE_ID}'"""
        self.dSql['updateReferralCode']                  = """UPDATE individuals SET referral_code = '{REFERRAL_CODE}' WHERE id='{INDIVIDUAL_ID}'"""
        self.dSql['updateCoveragePaymentWithoutLoading'] = """UPDATE coverages SET payment_without_loading = '{PAYMENT_WITHOUT_LOADING}' WHERE id='{COVERAGE_ID}'"""
        self.dSql['updateCoverageDateIncreaseUnpaid'] = """UPDATE coverages SET created_at = '{UPDATED_DATE}', updated_at='{UPDATED_DATE}', status='increase-unpaid' WHERE id='{COVERAGE_ID}'"""
        self.dSql['updateOrdersRetries']                   = """UPDATE orders SET retries='{RETRY_NUM}' WHERE id='{ORDER_ID}'"""

        # Delete
        self.dSql['deleteCoverages']        = """DELETE FROM coverages WHERE owner_id = '{OWNER_ID}' AND payer_id = '{PAYER_ID}'"""
        self.dSql['deleteSpecificCoverage'] = """DELETE FROM coverages WHERE owner_id = '{DEARTIME_MEMBERID}' AND product_id = '{PRODUCT_ID}'"""

    def exec_SQL(self, inKey, inDict, type=None):
        if not inDict:
            # tSQL1 = self.dSql[inKey].format_map(self.tDict)
            tSQL1 = self.dSql[inKey]
        else:
            tSQL1 = self.dSql[inKey].format_map(inDict)
        
        if type == 'fetchone':
            self.mycursor.execute(tSQL1)
            myresult = self.mycursor.fetchone()
            dname    = [ i[0] for i in self.mycursor.description ]
            self.dResult  = {
                "dset"    : myresult, 
                "dcolname": dname
            }
            self.mycursor.reset()
        elif type == 'fetchall':
            self.mycursor.execute(tSQL1)
            myresult = self.mycursor.fetchall()
            dset  = []
            dname = [ i[0] for i in self.mycursor.description ]
            for x in myresult:
                dset.append(x)
                
            self.dResult = {
                "dset"    : dset, 
                "dcolname": dname
            }
            self.mycursor.reset()
        elif type == 'insert':
            try:
                myresult = self.mycursor.execute(tSQL1, inDict)
                self.mydb.commit()
                self.dResult = {
                    "lastID": self.mycursor.lastrowid,
                }
            except Exception as ex:
                logger.error(str(ex))
                if ex.errno == 1062:
                    self.dResult = {
                        "error": '{} has already existed! Please contact IT Administrator to proceed.'.format(inDict[4]),
                    }
                else:
                    self.dResult = {
                        "error": str(ex),
                    }
        elif type == 'update':
            try:
                myresult = self.mycursor.execute(tSQL1, inDict)
                self.mydb.commit()
                self.dResult = {}
            except Exception as e:
                logger.error(str(e))
                self.dResult = {
                    "error": str(e)
                }
        elif type == 'delete':
            try:
                myresult = self.mycursor.execute(tSQL1, inDict)
                self.mydb.commit()
                self.dResult = {}
            except Exception as e:
                logger.error(str(e))
                self.dResult = {
                    "error": str(e)
                }
        return self.dResult

class AddressMapping():
    def connect(self):
        self.isConnected = True
        self.getSQLConnection    = DearTimeDbConn()
        isConnected         = self.getSQLConnection.connect()
        if not isConnected:
            self.isConnected = False
        return self.isConnected

    def prepData(self, query):
        prepped = []
        for data in query:
            for i in data:
                prepped.append(i)
        return prepped

    def queryCity(self):
        return dict(self.getSQLConnection.exec_SQL('cities', False, type='fetchall')['dset'])

    def queryPost(self):
        return dict(self.getSQLConnection.exec_SQL('postal_codes', False, type='fetchall')['dset'])

    def queryState(self):
        return self.prepData(self.getSQLConnection.exec_SQL('states', False, type='fetchall')['dset'])

class GetCoverages():
    #Member dependent else package dependent
    def getCoverages(self, dependent, flag):
        getProductQS             = Product.objects.filter(is_active=True)
        if flag == 1:
            getMapping = MemberProductMapping.objects.filter(member_id=dependent.id, is_terminated=False, is_renewal=False)
        elif flag == 2:
            getMapping = PackageProductMapping.objects.filter(package_id=dependent.id)
        getCoverages             = {}
        if getMapping:
            for prd in getProductQS:
                if not getMapping.filter(product_id=prd.id):
                    getCoverages[prd.product_name] = None
                else:
                    getCoverages[prd.product_name] = getMapping.get(product_id=prd.id).coverage_amount
        else:
            for prd2 in getProductQS:
                getCoverages[prd2.product_name] = None
        return getCoverages

class GetMembers():
    def getMembers(self, **kwargs):
        filter_dict = {}
        for key, value in kwargs.items():
            filter_dict[key] = value

        membersDict = []
        rowcount    = 5
        getCompanyMembers = Member.objects.filter(**filter_dict)
        getCoveragesObj   = GetCoverages()
        for cmpmem in getCompanyMembers:
            getPackageObj            = Package.objects.get(id=cmpmem.package_id)
            getCoverages             = getCoveragesObj.getCoverages(cmpmem, 1)
            serializerCMP = json.loads(serializers.serialize('json', [cmpmem]))
            serializerCMP[0]['fields'].update({
                'id'      : serializerCMP[0]['pk'],
                'package' : getPackageObj,
                'coverage': getCoverages
            })
            membersDict.append(serializerCMP[0]['fields'])
        self.membersTable = Paginator(membersDict, rowcount)
        return self.membersTable

class GetCompanies():
    def getCompanies(self, **kwargs):
        filter_dict = {}
        for key, value in kwargs.items():
            filter_dict[key] = value
            
        companiesDict = []
        rowcount      = 5
        getCompanies  = CorporateProfile.objects.filter(**filter_dict)
        for cmp in getCompanies:
            serializerCMP = json.loads(serializers.serialize('json', [cmp]))
            serializerCMP[0]['fields'].update({
                'id'      : serializerCMP[0]['pk'],
            })
            companiesDict.append(serializerCMP[0]['fields'])
        self.companiesTable = Paginator(companiesDict, rowcount)
        return self.companiesTable

class GetMedicalPlans():
    def connect(self):
        self.isConnected      = True
        self.getSQLConnection = DearTimeDbConn()
        isConnected           = self.getSQLConnection.connect()
        if not isConnected:
            self.isConnected  = False
        return self.isConnected

    def getMedical(self, deartimeDB):
        plans_dict = json.loads(deartimeDB.exec_SQL('getMedicalPlans', False, type='fetchone')['dset'][0])
        deductibles = []
        for plan in plans_dict["plans"]:
            deductibles.append(plan["deductible"])
        return deductibles

class CheckUniquePackage():

    def check(self, coverages, company_user_id, company_campaign_code):
        self.existPackage = False
        self.matchCount = 0
        if company_campaign_code:
            getMappings = PackageProductMapping.objects.all()
            getPackages = Package.objects.filter(under_campaign=company_campaign_code) 
        else:
            getMappings = PackageProductMapping.objects.filter(created_by_id=company_user_id)
            getPackages = Package.objects.filter(created_by_id=company_user_id)
        for pkg in getPackages:
            self.matchCount = 0
            for mpg in getMappings:
                if mpg.package == pkg:
                    if mpg.coverage_amount == int(coverages[mpg.product.product_name]):
                        self.matchCount += 1
                if self.matchCount == len(list(Product.objects.filter(is_active=True))):
                    return pkg
        return []

class PremiumCalculator():
    def connect(self):
        self.isConnected      = True
        self.getSQLConnection = DearTimeDbConn()
        isConnected           = self.getSQLConnection.connect()
        if not isConnected:
            self.isConnected  = False
        return self.isConnected

    #To update the payment due date to next due date
    def checkPaymentDueDate(self, dueDate, corporateID, paymentMode):
        self.corporate = CorporateProfile.objects.get(id=corporateID)

        # Payment due date 
        splitDueDate = dueDate.split('-')
        month = int(splitDueDate[1])
        day = int(splitDueDate[2])

        # Current date
        currentDate = GenericLibraries().currentDateTesting(corporateID, True)
        currentYear = currentDate.year
        currentMonth = currentDate.month

        dueDate = datetime.datetime.strptime(dueDate, '%Y-%m-%d')
            
        if paymentMode == 'Monthly':
            if dueDate <= currentDate:
                try:
                    if dueDate.day > currentDate.day:
                        dueDate = datetime.datetime(currentYear, currentMonth, day)
                    else:
                        currentMonth = currentMonth + 1
                        try:
                            dueDate = datetime.datetime(currentYear, currentMonth, day)
                        except ValueError:
                            currentYear = currentYear + 1
                            currentMonth = 1
                            dueDate = datetime.datetime(currentYear, currentMonth, day)
                except ValueError:
                    numDaysinMonth = monthrange(currentYear, currentMonth)[1]
                    dueDate = datetime.datetime(currentYear, currentMonth, numDaysinMonth)
                    dueDate = dueDate + timedelta(days=1)
        else:
            # If payment due date is less than today's date, add one year to the current year
            if dueDate <= currentDate:
                try: 
                    if dueDate.day > currentDate.day and dueDate.month > currentDate.month:
                        dueDate = datetime.datetime(currentYear, month, day)
                    else:
                        currentYear = currentYear + 1
                        dueDate = datetime.datetime(currentYear, month, day)
                except ValueError:
                    numDaysinMonth = monthrange(currentYear, month)[1]
                    dueDate = datetime.datetime(currentYear, month, numDaysinMonth)
                    dueDate = dueDate + timedelta(days=1)

        self.corporate.payment_due_date = dueDate.strftime('%Y-%m-%d')
        self.corporate.save()
        
        # if isleap(currentYear):
        #     formatPaymentDueDate = datetime.datetime(currentYear, currentMonth, day)
        #     self.corporate.payment_due_date = formatPaymentDueDate.strftime('%Y-%m-%d')
        #     self.corporate.save()

        # else:
        # if day <= numDaysinMonth:
        #     # If day is present in the current month then get current year and month
        #     if paymentMode == 'Monthly':
        #         formatPaymentDueDate = datetime.datetime(currentYear, currentMonth, day)
        #         self.corporate.payment_due_date = formatPaymentDueDate.strftime('%Y-%m-%d')
        #         self.corporate.save()
        #     else:
        #         # annually mode
        #         formatPaymentDueDate = datetime.datetime(currentYear, month, day)
        #         self.corporate.payment_due_date = formatPaymentDueDate.strftime('%Y-%m-%d')
        #         self.corporate.save()
        # else:
        #     # If day is not in the present month then add 1 day
        #     if paymentMode == 'Monthly':
        #         formatPaymentDueDate = datetime.datetime(currentYear, currentMonth, numDaysinMonth)
        #         finalizedPaymentDueDate = formatPaymentDueDate + datetime.timedelta(days=1)
        #         self.corporate.payment_due_date = finalizedPaymentDueDate.strftime('%Y-%m-%d')
        #         self.corporate.save()
        #     else:
        #         # annually mode
        #         formatPaymentDueDate = datetime.datetime(currentYear, month, numDaysinMonth)
        #         finalizedPaymentDueDate = formatPaymentDueDate + datetime.timedelta(days=1)
        #         self.corporate.payment_due_date = finalizedPaymentDueDate.strftime('%Y-%m-%d')
        #         self.corporate.save()            
                    
        return self.corporate.payment_due_date

    def calculate_fields(self, DTmemberID, corporateID, deartimeDB, isExist):
        current = GenericLibraries().currentDateTesting(corporateID, True)
        self.member = Member.objects.get(deartime_memberid=DTmemberID, corporate_id=corporateID, is_deleted=False, is_existing=isExist)
        self.corporate = CorporateProfile.objects.get(id=self.member.corporate_id)
        self.age = current.year - self.member.dob.year - ((current.month, current.day) < (self.member.dob.month, self.member.dob.day))
        self.gender = 1 if self.member.gender[0].lower() == 'm' else 2
        self.job = deartimeDB.exec_SQL('getJob', {'DEARTIME_MEMBERID': self.member.deartime_memberid}, 'fetchone')['dset'][0]
        self.loadingQS = deartimeDB.exec_SQL('getLoading', {'JOB_ID': self.job}, 'fetchone')
        self.loading = {}
        self.lrd = {}
        self.nrd = {}
        self.nnrd = {}
        self.emloading = {}
        self.premium = {}
        self.coverage = {}
        self.total = 0.00
        self.frequency = 1.00
        self.products = Product.objects.filter(is_active=True)

    def round_up(self, number_to_round_up):
        return math.ceil(number_to_round_up * 100) / 100

    def calculate_emloading(self, DTmemberID, deartimeDB, renewal = None):
        getIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
        if renewal:
            getUnderwritingDict = deartimeDB.exec_SQL('getUnderwritingAnswerRenewal', {'INDIVIDUAL_ID': getIndividual['dset'][0],'PAYER_ID': self.corporate.deartime_payerid}, 'fetchone')
        else:
            getUnderwritingDict = deartimeDB.exec_SQL('getUnderwritingAnswer', {'INDIVIDUAL_ID': getIndividual['dset'][0]}, 'fetchone')

        self.products = Product.objects.filter(is_active=True)
        underwriting_question = '1,2,3'
        if getUnderwritingDict['dset']:
            if not None in getUnderwritingDict['dset']:
                getUnderwritingAnswer = json.loads(getUnderwritingDict['dset'][0])
                getUnderwritingAnswerDict = getUnderwritingAnswer['answers']
                formattedDigestiveItem = ''
                count = 1
                for ans in getUnderwritingAnswerDict:
                    if count == len(getUnderwritingAnswerDict):
                        formattedDigestiveItem += str(ans)
                    else:
                        formattedDigestiveItem += str(ans) + ','
                    count+=1
                for prd in self.products:
                    total_emloading = 0
                    is_eligible = True
                    for answer in getUnderwritingAnswerDict:
                        if is_eligible:
                            eligibility = deartimeDB.exec_SQL('getUnderwritingProductEligibility', {'UW_ID': answer, 'GROUP_ID': underwriting_question}, 'fetchone')
                            if eligibility['dset']:
                                if prd.product_name == 'Critical Illness':
                                    productEligible = eligibility['dset'][eligibility['dcolname'].index('critical_illiness')]
                                else:
                                    productEligible = eligibility['dset'][eligibility['dcolname'].index(str(prd.product_name).lower().replace(" ","_"))]
                                if productEligible:
                                    emloading = deartimeDB.exec_SQL('getUnderwritingProductLoading', {'UW_ID': answer, 'PRODUCT_NAME':prd.product_name}, 'fetchone')
                                    if emloading['dset']:
                                        total_emloading +=  emloading['dset'][0]
                                    else:
                                        total_emloading +=  0
                                else:
                                    is_eligible = False
                                    total_emloading = 0
                    self.emloading[prd.product_name] = total_emloading/100.00
            else:
                for prd in self.products:
                    self.emloading[prd.product_name] = 0
        else:
            for prd in self.products:
                self.emloading[prd.product_name] = 0

    def calculate_lrd(self, deartimeDB, renewal2 = None, old_lrd = None, getMemberIndividual = None, getCorporateIndividual = None, changePayment = None, changePaymentNextRenewal = None, withoutLoading = None, has_CampaignCode = None):
        self.products = Product.objects.filter(is_active=True)
        for prd in self.products:
            self.coverage[prd.product_name] = float(MemberProductMapping.objects.get(member=self.member, product=prd, is_terminated=False, is_renewal= (True if renewal2 is True else False)).coverage_amount)
            if int(self.coverage[prd.product_name]) != 0:
                if renewal2 or old_lrd or changePayment:
                    coverageDates = deartimeDB.exec_SQL('getCoveragePaymentDates', {'OWNER_ID': getMemberIndividual['dset'][0], 'PAYER_ID': getCorporateIndividual.deartime_payerid, 'PRODUCT_NAME': prd.product_name}, 'fetchone')
                    last_payment_date = coverageDates['dset'][coverageDates['dcolname'].index('last_payment_on')]
                    next_renewal_date = coverageDates['dset'][coverageDates['dcolname'].index('next_payment_on')]
                    renewal_date = last_payment_date + relativedelta(years=1)
                    age_on_last_payment_date = relativedelta(last_payment_date, self.member.dob)
                    age_on_renewal_date = relativedelta(renewal_date, self.member.dob)
                    if changePaymentNextRenewal:
                        next_next_renewal_date = next_renewal_date + relativedelta(years=1)
                        age_on_next_renewal_date = relativedelta(next_next_renewal_date, self.member.dob)
                if prd.product_name != 'Medical':
                    getOptionsDict = deartimeDB.exec_SQL('getPremiumRate', {'PRODUCT_NAME': prd.product_name}, 'fetchone')
                    if getOptionsDict['dset']:
                        getPremiumRateOptions = json.loads(getOptionsDict['dset'][0])
                        if (has_CampaignCode):
                            # get the rate for the campaign
                            getPremiumRateDict = getPremiumRateOptions['campaign_uw_loading']
                        else:
                            # remain the same
                            getPremiumRateDict = getPremiumRateOptions['premium_rates']
                            
                        for rate in getPremiumRateDict:
                            if renewal2 or old_lrd or changePayment:
                                if changePaymentNextRenewal:
                                    if rate[0] == age_on_next_renewal_date.years:
                                        self.nextRenewalRate = rate[self.gender]
                                else:
                                    self.nextRenewalRate = 0
                                if rate[0] == age_on_last_payment_date.years:
                                    self.rate = rate[self.gender]
                                elif rate[0] == age_on_renewal_date.years:
                                    self.oldRate = rate[self.gender]
                            else:
                                if rate[0] == self.age:
                                    self.rate = rate[self.gender]
                                    self.oldRate = 0
                                    self.nextRenewalRate = 0
                else:
                    getMedical = deartimeDB.exec_SQL('getMedicalPlans', {}, 'fetchone')
                    if getMedical['dset']:
                        getMedicalRateOptions = json.loads(getMedical['dset'][0])
                        getMedicalPlan = getMedicalRateOptions['plans']
                        for plan in getMedicalPlan:
                            if plan['deductible'] == self.coverage['Medical']:
                                getMedicalRateDict = plan['premium_rates']
                                for rate in getMedicalRateDict:
                                    if renewal2 or old_lrd or changePayment:
                                        if changePaymentNextRenewal:
                                            if rate[0] == age_on_next_renewal_date.years:
                                                self.nextRenewalRate = rate[self.gender]
                                        else:
                                            self.nextRenewalRate = 0
                                        if rate[0] == age_on_last_payment_date.years:
                                            self.rate = rate[self.gender]
                                        elif rate[0] == age_on_renewal_date.years:
                                            self.oldRate = rate[self.gender]
                                    else:
                                        if rate[0] == self.age:
                                            self.rate = rate[self.gender]
                                            self.oldRate = 0
                                            self.nextRenewalRate = 0

                if prd.product_name == 'Critical Illness':
                    self.loading[prd.product_name] = 0
                    #Calculate premium without loading
                    if withoutLoading:
                        self.emloading[prd.product_name] = 0
                    self.lrd[prd.product_name]     = self.round_up((self.rate * self.coverage[prd.product_name] / 1000.00) * (1 + self.emloading[prd.product_name]) * self.frequency)
                    self.nrd[prd.product_name]     = self.round_up((self.oldRate * self.coverage[prd.product_name] / 1000.00) * (1 + self.emloading[prd.product_name]) * self.frequency)
                    self.nnrd[prd.product_name]    = self.round_up((self.nextRenewalRate * self.coverage[prd.product_name] / 1000.00) * (1 + self.emloading[prd.product_name]) * self.frequency)
                elif prd.product_name == 'Disability':
                    self.loading[prd.product_name] = abs(self.loadingQS['dset'][self.loadingQS['dcolname'].index('TPD')])
                    if withoutLoading:
                        self.loading[prd.product_name] = 1
                        self.emloading[prd.product_name] = 0
                    self.lrd[prd.product_name]     = self.round_up(((self.rate * self.coverage[prd.product_name] / 1000.00) * (self.loading[prd.product_name] + self.emloading[prd.product_name])) * self.frequency)
                    self.nrd[prd.product_name]     = self.round_up(((self.oldRate * self.coverage[prd.product_name] / 1000.00) * (self.loading[prd.product_name] + self.emloading[prd.product_name])) * self.frequency)
                    self.nnrd[prd.product_name]    = self.round_up(((self.nextRenewalRate * self.coverage[prd.product_name] / 1000.00) * (self.loading[prd.product_name] + self.emloading[prd.product_name])) * self.frequency)
                elif prd.product_name == 'Medical':
                    self.loading[prd.product_name] = abs(self.loadingQS['dset'][self.loadingQS['dcolname'].index(prd.product_name)])
                    if withoutLoading:
                        self.loading[prd.product_name] = 1
                        self.emloading[prd.product_name] = 0
                    self.lrd[prd.product_name]     = self.round_up(self.rate * (self.loading[prd.product_name] + self.emloading[prd.product_name]) * self.frequency)
                    self.nrd[prd.product_name]     = self.round_up(self.oldRate * (self.loading[prd.product_name] + self.emloading[prd.product_name]) * self.frequency)
                    self.nnrd[prd.product_name]    = self.round_up(self.nextRenewalRate * (self.loading[prd.product_name] + self.emloading[prd.product_name]) * self.frequency)
                elif prd.product_name == 'Death':
                    self.loading[prd.product_name] = abs(self.loadingQS['dset'][self.loadingQS['dcolname'].index('death')])
                    if withoutLoading:
                        self.loading[prd.product_name] = 0
                        self.emloading[prd.product_name] = 0
                    self.lrd[prd.product_name]     = self.round_up((((self.rate + self.loading[prd.product_name]) * self.coverage[prd.product_name] / 1000.00) + (self.rate * self.coverage[prd.product_name] / 1000.00) * self.emloading[prd.product_name]) * self.frequency)
                    self.nrd[prd.product_name]     = self.round_up((((self.oldRate + self.loading[prd.product_name]) * self.coverage[prd.product_name] / 1000.00) + (self.oldRate * self.coverage[prd.product_name] / 1000.00) * self.emloading[prd.product_name]) * self.frequency)
                    self.nnrd[prd.product_name]    = self.round_up((((self.nextRenewalRate + self.loading[prd.product_name]) * self.coverage[prd.product_name] / 1000.00) + (self.oldRate * self.coverage[prd.product_name] / 1000.00) * self.emloading[prd.product_name]) * self.frequency)
                elif prd.product_name == 'Accident':
                    self.loading[prd.product_name] = abs(self.loadingQS['dset'][self.loadingQS['dcolname'].index(prd.product_name)])
                    if withoutLoading:
                        self.loading[prd.product_name] = 1
                        self.emloading[prd.product_name] = 0
                    self.lrd[prd.product_name]     = self.round_up(((self.rate * self.coverage[prd.product_name] / 1000.00) * (self.loading[prd.product_name] + self.emloading[prd.product_name])) * self.frequency)
                    self.nrd[prd.product_name]     = self.round_up(((self.oldRate * self.coverage[prd.product_name] / 1000.00) * (self.loading[prd.product_name] + self.emloading[prd.product_name])) * self.frequency)
                    self.nnrd[prd.product_name]    = self.round_up(((self.nextRenewalRate * self.coverage[prd.product_name] / 1000.00) * (self.loading[prd.product_name] + self.emloading[prd.product_name])) * self.frequency)

    def calculate_premium(self, DTmemberID, corporateID, result, memberProductMapping, deartimeDB, renewal = None, old_lrd = None, trueAmount = None, withoutLoadings = None, memberCampaignCode = None, memberExisting = None):
        currentDate = datetime.datetime.now()
        if settings.ENVIRONMENT_INDICATOR != '':
            preferredCurrentDate = CurrentDate.objects.filter(corporate_id=corporateID)
            if preferredCurrentDate:
                currentObject = CurrentDate.objects.get(corporate_id=corporateID)
                currentDate = currentObject.current_datetime
            else:
                currentDate = datetime.datetime.today()
        else:
            currentDate = datetime.datetime.today()
      
        getMemberIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
        getCorporateIndividual = CorporateProfile.objects.get(id=corporateID)
        hasCampaignCode = None
        isExist = 0
        
        if memberCampaignCode:
            withoutLoadings = True
            hasCampaignCode = True
            
        if memberExisting:
            isExist = 1
            
        self.calculate_fields(DTmemberID, corporateID, deartimeDB, isExist)
        if self.corporate.payment_mode == 'Monthly':
            self.frequency = 0.085
        if old_lrd:
            self.calculate_emloading(DTmemberID, deartimeDB, renewal)
            self.calculate_lrd(deartimeDB, None, old_lrd, getMemberIndividual, getCorporateIndividual, None, None, withoutLoadings, hasCampaignCode)
        elif renewal:
            self.calculate_emloading(DTmemberID, deartimeDB, renewal)
            self.calculate_lrd(deartimeDB, renewal, None, getMemberIndividual, getCorporateIndividual, None, None, withoutLoadings, hasCampaignCode)
        else:
            self.calculate_emloading(DTmemberID, deartimeDB)
            self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, None, None, withoutLoadings, hasCampaignCode)
        
        # else:
        #     self.calculate_fields(DTmemberID, corporateID, deartimeDB)
        #     if self.corporate.payment_mode == 'Monthly':
        #         self.frequency = 0.085
        #     if old_lrd:
        #         self.calculate_lrd(deartimeDB, None, old_lrd, getMemberIndividual, getCorporateIndividual, None, None, withoutLoadings)
        #     elif renewal:
        #         self.calculate_lrd(deartimeDB, renewal, None, getMemberIndividual, getCorporateIndividual, None, None, withoutLoadings)
        #     else:
        #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, None, None, withoutLoadings)
            
        totalPremiumLRD = 0
        premium_due_date = datetime.datetime.strptime(self.corporate.payment_due_date, '%Y-%m-%d')
        
        for k, v in self.coverage.items():
            for prd in self.products:
                if prd.product_name == k and v != 0:
                    if withoutLoadings:
                        if renewal:
                            self.premium[prd.product_name] = round(self.nrd[prd.product_name], 2)
                        else:
                            totalPremiumLRD = totalPremiumLRD + self.lrd[prd.product_name]
                            self.premium[prd.product_name] = round(self.lrd[prd.product_name], 2)
                    else:
                        if renewal:
                            coverageDates = deartimeDB.exec_SQL('getCoveragePaymentDates', {'OWNER_ID': getMemberIndividual['dset'][0], 'PAYER_ID': getCorporateIndividual.deartime_payerid, 'PRODUCT_NAME': prd.product_name}, 'fetchone')
                            # Premium Renewal calculation
                            last_payment_date = coverageDates['dset'][coverageDates['dcolname'].index('last_payment_on')]
                            renewal_date = last_payment_date + relativedelta(years=1)
                            ndd_payment_due_date = coverageDates['dset'][coverageDates['dcolname'].index('ndd_payment_due_date')]
                            next_premium_date = ndd_payment_due_date + relativedelta(years=1)
                            getTotalDays = (next_premium_date - ndd_payment_due_date).days
                            self.premium[prd.product_name] = round((round(self.lrd[prd.product_name], 2) * (float((renewal_date.date() - ndd_payment_due_date.date()).days) / getTotalDays)) + (round(self.nrd[prd.product_name],2) * (float((next_premium_date.date() - renewal_date.date()).days) / getTotalDays)), 2)                                      
                        else:
                            if self.corporate.payment_mode == 'Monthly':
                                LDD = premium_due_date - relativedelta(months=1)
                                getTotalDays = (premium_due_date - LDD).days
                            else:
                                LDD = premium_due_date - relativedelta(years=1)
                                getTotalDays = (premium_due_date - LDD).days
                            totalPremiumLRD = totalPremiumLRD + self.lrd[prd.product_name]
                            self.premium[prd.product_name] = round(self.lrd[prd.product_name] * (float((premium_due_date.date() - currentDate.date()).days) / getTotalDays), 2)

        if withoutLoadings:
            for k1, v1 in self.premium.items():
                for mpm in memberProductMapping:
                    if mpm.deartime_coverageid and mpm.product.product_name.lower() == k1.lower():
                        updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragePaymentWithoutLoading', {'PAYMENT_WITHOUT_LOADING': v1, 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')  
            
            #execute if only having one coverage
            if len(self.premium) == 1:
                return next(iter(self.premium.values()), 0)
            else:
                # return sum(self.premium.values())
                return self.premium
        else:
            if result == 'specific':
                return self.premium
            elif result == 'total':
                getIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
                getThankgivings = deartimeDB.exec_SQL('getThanksGiving', {'INDIVIDUAL_ID': getIndividual['dset'][0]}, 'fetchone')
                for k2, v2 in self.premium.items():
                    if trueAmount:
                        amount = round(v2,2)
                    else:
                        if getThankgivings['dset']:
                            # if got record, then only multiply
                            thankgiving = v2 * float(getThankgivings['dset'][0] / 10 / 100)
                            # amount = round(v2-thankgiving,2)
                            amount = float(Decimal(str(v2 - thankgiving)).quantize(Decimal('0.00'), rounding=ROUND_HALF_UP))
                        else:
                            # if no then zero
                            thankgiving = v2 * float(0 / 10 / 100)
                            amount = round(v2 - thankgiving,2)
                        for mpm in memberProductMapping:
                            if mpm.deartime_coverageid and mpm.product.product_name.lower() == k2.lower():
                                if renewal:
                                    if self.corporate.payment_mode == 'Monthly':
                                        updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.premium[k2],2)), 'PAYMENT_ANNUALLY': str(round(self.premium[k2]*12,2)), 'FULL_PREMIUM': str(round(self.lrd[k2],2)), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                    else:
                                        updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.premium[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.premium[k2]), 'FULL_PREMIUM': str(self.lrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                    # if self.corporate.payment_mode == 'Monthly':
                                    #     updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.premium[k2],2)), 'PAYMENT_ANNUALLY': str(round(self.premium[k2]*12,2)), 'FULL_PREMIUM': str(round(self.premium[k2],2)), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                    # else:
                                    #     updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.premium[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.premium[k2]), 'FULL_PREMIUM': str(self.premium[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                else:
                                    # if self.corporate.payment_mode == 'Monthly':
                                    #     updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.lrd[k2],2)), 'PAYMENT_ANNUALLY': str(round(self.lrd[k2]*12,2)), 'FULL_PREMIUM': str(round(self.lrd[k2],2)), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                    # else:
                                    #     updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.lrd[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.lrd[k2]), 'FULL_PREMIUM': str(self.lrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                    if self.corporate.payment_mode == 'Monthly':
                                        updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.premium[k2],2)), 'PAYMENT_ANNUALLY': str(round(self.premium[k2]*12,2)), 'FULL_PREMIUM': str(round(self.lrd[k2],2)), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                                    else:
                                        updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.premium[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.premium[k2]), 'FULL_PREMIUM': str(self.lrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                    self.total += amount
                return round(self.total, 2)

    #calulate remaining premium when payment mode has been changed from monthly to yearly
    def calculate_changed_premium(self, DTmemberID, corporateID, result, memberProductMapping, deartimeDB, trueAmount=None):
        currentDate = datetime.datetime.now()
        getMemberIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
        getCorporateIndividual = CorporateProfile.objects.get(id=corporateID)
        self.calculate_fields(DTmemberID, corporateID, deartimeDB)
        self.calculate_emloading(DTmemberID, deartimeDB, True)
        getChangePaymentMode = PaymentModeHistory.objects.filter(corporate_id=getCorporateIndividual.id, is_updated=False, is_void=False)
        if getChangePaymentMode:
            latestChangePaymentMode = PaymentModeHistory.objects.latest("created_datetime")
            newNDD = latestChangePaymentMode.new_payment_due_date
        else:
            newNDD = getCorporateIndividual.payment_due_date
        splitNewNDD = newNDD.split('-')
        month = int(splitNewNDD[1])
        day = int(splitNewNDD[2])
        newNDD = datetime.datetime.strptime(newNDD, '%Y-%m-%d')
        premium_due_date = datetime.datetime.strptime(self.corporate.payment_due_date, '%Y-%m-%d')
        oldNDD = premium_due_date
        currentYear = oldNDD.year
        policyYearOldNDD = 0
        policyYearNewNDD = 0
        if newNDD <= oldNDD:
            try: 
                if newNDD.day > oldNDD.day and newNDD.month > oldNDD.month:
                    newNDD = datetime.datetime(currentYear, month, day)
                else:
                    currentYear = currentYear + 1
                    newNDD = datetime.datetime(currentYear, month, day)
            except ValueError:
                numDaysinMonth = monthrange(currentYear, month)[1]
                newNDD = datetime.datetime(currentYear, month, numDaysinMonth)
                newNDD = newNDD + timedelta(days=1)
        newLDD = newNDD - relativedelta(years=1)

        memberCoverage = deartimeDB.exec_SQL('getCoveragesDates', {'OWNER_ID': getMemberIndividual['dset'][0], 'PAYER_ID': getCorporateIndividual.deartime_payerid}, 'fetchone')
        LRD = memberCoverage['dset'][memberCoverage['dcolname'].index('first_payment_on')]
        NRD = memberCoverage['dset'][memberCoverage['dcolname'].index('next_payment_on')]
        NNRD = NRD + relativedelta(years=1)

        if oldNDD >= NNRD:
            policyYearOldNDD = 3
        elif oldNDD >= NRD:
            policyYearOldNDD = 2
        elif oldNDD >= LRD:
            policyYearOldNDD = 1

        if newNDD >= NNRD:
            policyYearNewNDD = 3
        elif newNDD >= NRD:
            policyYearNewNDD = 2
        elif newNDD >= LRD:
            policyYearNewNDD = 1
      
        # if newNDD >= LRD:
        #     policyYearNewNDD = 1
        # elif newNDD >= NRD:
        #     policyYearNewNDD = 2
        # elif newNDD >= NNRD:
        #     policyYearNewNDD = 3

        self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, True, True)

        # if policyYearNewNDD == 1:
        #     self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual)
        # elif policyYearNewNDD == 2:
        #     self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, True)
        # else:
        #     self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, True, True)   

        # if newNDD.year == oldNDD.year:
        #     if newNDD.year == currentYear:
        #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual)
        #     else:
        #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, True)
        # else:
        #     if (newNDD.year - currentDate.year) <= 1:
        #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, True)
        #     else:
        #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, True, True)   
        firstRate= 0
        secondRate = 0 
        firstEffectiveNDDRate = 0
        secondEffectiveNDDRate = 0
        getTotalDays = (newNDD.date() - newLDD.date()).days

        if policyYearOldNDD == policyYearNewNDD:
            firstEffectiveNDDRate =  (newNDD.date() - oldNDD.date()).days / getTotalDays
        else:
            if policyYearOldNDD == 1:
               firstEffectiveNDDRate = (NRD.date() - oldNDD.date()).days / getTotalDays
               secondEffectiveNDDRate = (newNDD.date() - NRD.date()).days / getTotalDays
            else:
                firstEffectiveNDDRate = (NNRD.date() - oldNDD.date()).days / getTotalDays
                secondEffectiveNDDRate = (newNDD.date() - NNRD.date()).days / getTotalDays
        
        for k, v in self.coverage.items():
            for prd in self.products:
                if prd.product_name == k and v != 0:
                    if policyYearOldNDD == 1:
                        firstRate = self.lrd[prd.product_name]
                    elif policyYearOldNDD == 2:
                        firstRate = self.nrd[prd.product_name]
                    else:
                        firstRate = self.nnrd[prd.product_name]

                    if policyYearNewNDD == 1:
                        secondRate = self.lrd[prd.product_name]
                    elif policyYearNewNDD == 2:
                        secondRate = self.nrd[prd.product_name]
                    else:
                        secondRate = self.nnrd[prd.product_name]
                    self.premium[prd.product_name] = float(Decimal(str((firstRate * firstEffectiveNDDRate) + (secondRate * secondEffectiveNDDRate))).quantize(Decimal('0.00'), rounding=ROUND_HALF_UP))
                    # if newNDD.year == oldNDD.year:
                    #     if newNDD.year == currentYear:
                    #         self.premium[prd.product_name] = round(self.lrd[prd.product_name] * (float((newNDD.date() - oldNDD.date()).days) / (newNDD.date() - newLDD.date()).days), 2)
                    #     else:
                    #         self.premium[prd.product_name] = round(self.nrd[prd.product_name] * (float((newNDD.date() - oldNDD.date()).days) / (newNDD.date() - newLDD.date()).days), 2)
                    # else:
                    #     if (newNDD.year - currentDate.year) <= 1:
                    #         self.premium[prd.product_name] = round((self.lrd[prd.product_name] * (float((NRD.date() - oldNDD.date()).days) / (newNDD.date() - newLDD.date()).days)) + (self.nrd[prd.product_name] * (float((newNDD.date() - NRD.date()).days) / (newNDD.date() - newLDD.date()).days)), 2)
                    #     else:
                    #         self.premium[prd.product_name] = round((self.nrd[prd.product_name] * (float((NNRD.date() - oldNDD.date()).days) / (newNDD.date() - newLDD.date()).days)) + (self.nnrd[prd.product_name] * (float((newNDD.date() - NRD.date()).days) / (newNDD.date() - newLDD.date()).days)), 2)       
                    print("prd:", prd.product_name)
                    print("firstRate:", firstRate)
                    print("secondRate:", secondRate)
                    print("firstEffectiveNDDRate:", firstEffectiveNDDRate)
                    print("secondEffectiveNDDRate:", secondEffectiveNDDRate)
                    print("policyYearOldNDD:", policyYearOldNDD)
                    print("policyYearNewNDD:", policyYearNewNDD)
                    print("newNDD", newNDD)
                    print("oldNDD", oldNDD)
                    print("NRD", NRD)
                    print("premium:", self.premium[prd.product_name])
        if result == 'specific':
            return self.premium
        elif result == 'total':
            getIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
            getThankgivings = deartimeDB.exec_SQL('getThanksGiving', {'INDIVIDUAL_ID': getIndividual['dset'][0]}, 'fetchone')
            for k2, v2 in self.premium.items():
                if policyYearOldNDD == 1:
                    firstRate = self.lrd[k2]
                elif policyYearOldNDD == 2:
                    firstRate = self.nrd[k2]
                else:
                    firstRate = self.nnrd[k2]
              
                if trueAmount:
                    amount = round(v2,2)
                else:
                    if getThankgivings['dset']:
                        thankgiving = v2 * float(getThankgivings['dset'][0] / 10 / 100)
                        amount = float(Decimal(str(v2-thankgiving)).quantize(Decimal('0.00'), rounding=ROUND_HALF_UP))
                    else:
                        thankgiving = v2 * float(0 / 10 / 100)
                        amount = round(v2-thankgiving,2)
                    for mpm in memberProductMapping:
                        if mpm.deartime_coverageid and mpm.product.product_name.lower() == k2.lower():
                            # if self.corporate.payment_mode == 'Monthly':
                            #     updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(firstRate/12,2)), 'PAYMENT_ANNUALLY': str(firstRate), 'FULL_PREMIUM': str(round(firstRate/12,2)), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                            # else:
                            updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(firstRate/12,2)), 'PAYMENT_ANNUALLY': str(firstRate), 'FULL_PREMIUM': str(firstRate), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                            # if newNDD.year == oldNDD.year:
                            #     if newNDD.year == currentYear:
                            #         updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.lrd[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.lrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                            #     else:
                            #         updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.nrd[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.nrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                            # else:
                            #     if (newNDD.year - currentDate.year) <= 1:
                            #         updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.nrd[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.nrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                            #     else:
                            #         updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragesPayment', {'PAYMENT_MONTHLY': str(round(self.nnrd[k2]/12,2)), 'PAYMENT_ANNUALLY': str(self.nnrd[k2]), 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')       
                self.total += amount
        
            return round(self.total, 2)     

    # def calculate_true_amount(self, DTmemberID, corporateID, created, result, memberProductMapping, deartimeDB, renewal = None, old_lrd = None):
    #     currentYear = datetime.datetime.now().year
    #     currentDate = datetime.datetime.now()

    #     getMemberIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
    #     getCorporateIndividual = CorporateProfile.objects.get(id=corporateID)
        
    #     self.calculate_fields(DTmemberID, corporateID, deartimeDB)
    #     if self.corporate.payment_mode == 'Monthly':
    #         self.frequency = 0.085
    #     if old_lrd:
    #         self.calculate_emloading(DTmemberID, deartimeDB, renewal)
    #         self.calculate_lrd(deartimeDB, None, old_lrd, getMemberIndividual, getCorporateIndividual)
    #     elif renewal:
    #         self.calculate_emloading(DTmemberID, deartimeDB, renewal)
    #         self.calculate_lrd(deartimeDB, renewal, None, getMemberIndividual, getCorporateIndividual)
    #     else:
    #         self.calculate_emloading(DTmemberID, deartimeDB)
    #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual)
            
    #     totalPremiumLRD = 0
    #     premium_due_date = datetime.datetime.strptime(self.corporate.payment_due_date, '%Y-%m-%d')
            
    #     for k, v in self.coverage.items():
    #         for prd in self.products:
    #             if prd.product_name == k and v != 0:
    #                 if renewal:
    #                     coverageDates = deartimeDB.exec_SQL('getCoveragePaymentDates', {'OWNER_ID': getMemberIndividual['dset'][0], 'PAYER_ID': getCorporateIndividual.deartime_payerid, 'PRODUCT_NAME': prd.product_name}, 'fetchone')
    #                     # Premium Renewal calculation
    #                     last_payment_date = coverageDates['dset'][coverageDates['dcolname'].index('last_payment_on')]
    #                     renewal_date = last_payment_date + relativedelta(years=1)
    #                     ndd_payment_due_date = coverageDates['dset'][coverageDates['dcolname'].index('ndd_payment_due_date')]
    #                     next_premium_date = ndd_payment_due_date + relativedelta(years=1)
    #                     getTotalDays = (next_premium_date - ndd_payment_due_date).days
    #                     self.premium[prd.product_name] = round((round(self.lrd[prd.product_name], 2) * (float((renewal_date.date() - ndd_payment_due_date.date()).days) / getTotalDays)) + (round(self.nrd[prd.product_name],2) * (float((next_premium_date.date() - renewal_date.date()).days) / getTotalDays)), 2)
    #                 else:
    #                     LDD = premium_due_date - relativedelta(years=1)
    #                     getTotalDays = (premium_due_date - LDD).days
    #                     totalPremiumLRD = totalPremiumLRD + self.lrd[prd.product_name]
    #                     self.premium[prd.product_name] = round(self.lrd[prd.product_name] * (float((premium_due_date.date() - currentDate.date()).days) / getTotalDays), 2)

    #     if result == 'specific':
    #         return self.premium
    #     elif result == 'total':
    #         for k2, v2 in self.premium.items():
    #             amount = round(v2,2)
    #             self.total += amount
    #         return round(self.total, 2)

    def calculate_quotation(self, deartimeDB, memberObj, payment_mode, has_CampaignCode = None):
        current = datetime.datetime.today()
        products = Product.objects.filter(is_active=True)
        age = current.year - memberObj.dob.year - ((current.month, current.day) < (memberObj.dob.month, memberObj.dob.day))
        gender = 1 if memberObj.gender[0].lower() == 'm' else 2
        quotation = {}
        lrd = {}
        coverage = {}
        if payment_mode:
            if payment_mode == 'Monthly':
                frequency = 0.085
            else:
                frequency = 1.00
        else:
            frequency = 1.00
        getMemberProduct = MemberProductMapping.objects.filter(member=memberObj, is_terminated=False, is_renewal=False)
        if getMemberProduct:
            for prd in products:
                coverage[prd.product_name] = float(MemberProductMapping.objects.get(member=memberObj, product=prd, is_terminated=False, is_renewal=False).coverage_amount)
                if int(coverage[prd.product_name]) != 0:
                    if prd.product_name != 'Medical':
                        getOptionsDict = deartimeDB.exec_SQL('getPremiumRate', {'PRODUCT_NAME': prd.product_name}, 'fetchone')
                        if getOptionsDict['dset']:
                            getPremiumRateOptions = json.loads(getOptionsDict['dset'][0])
                            
                        if (has_CampaignCode):
                            # get the rate for the campaign
                            getPremiumRateDict = getPremiumRateOptions['campaign_uw_loading']
                        else:
                            # remain the same
                            getPremiumRateDict = getPremiumRateOptions['premium_rates']
                            
                        for rates in getPremiumRateDict:
                            if rates[0] == age:
                                rate = rates[gender]
                    else:
                        getMedical = deartimeDB.exec_SQL('getMedicalPlans', {}, 'fetchone')
                        if getMedical['dset']:
                            getMedicalRateOptions = json.loads(getMedical['dset'][0])
                            getMedicalPlan = getMedicalRateOptions['plans']
                            for plan in getMedicalPlan:
                                if plan['deductible'] == coverage['Medical']:
                                    getMedicalRateDict = plan['premium_rates']
                                    for rates in getMedicalRateDict:
                                        if rates[0] == age:
                                            rate = rates[gender]

                    if prd.product_name == 'Critical Illness':
                        lrd[prd.product_name]     = round((rate * coverage[prd.product_name] / 1000.00) * frequency, 5)
                    elif prd.product_name == 'Disability':
                        lrd[prd.product_name]     = round((rate * coverage[prd.product_name] / 1000.00) * frequency, 5)
                    elif prd.product_name == 'Medical':
                        lrd[prd.product_name]     = round(rate * frequency, 5)
                    elif prd.product_name == 'Death':
                        lrd[prd.product_name]     = round((rate * coverage[prd.product_name] / 1000.00) * frequency, 5)
                    elif prd.product_name == 'Accident':
                        lrd[prd.product_name]     = round((rate * coverage[prd.product_name] / 1000.00) * frequency, 5)
        
            totalPremiumLRD = 0
            for k, v in coverage.items():
                for prdt in products:
                    if prdt.product_name == k and v != 0:
                        quotation[prdt.product_name] = self.round_up(lrd[prdt.product_name])
                        totalPremiumLRD = totalPremiumLRD + quotation[prdt.product_name]
            return round(totalPremiumLRD, 2)
        else:
            return 0
    
    # def calculate_lrd_without_loading(self, deartimeDB, renewal = None, old_lrd = None, getMemberIndividual = None, getCorporateIndividual = None):
    #     self.products = Product.objects.filter(is_active=True)
    #     for prd in self.products:
    #         self.coverage[prd.product_name] = float(MemberProductMapping.objects.get(member=self.member, product=prd, is_terminated=False, is_renewal =(True if renewal is True else False)).coverage_amount)
    #         if int(self.coverage[prd.product_name]) != 0:
    #             if renewal or old_lrd:
    #                 coverageDates = deartimeDB.exec_SQL('getCoveragePaymentDates', {'OWNER_ID': getMemberIndividual['dset'][0], 'PAYER_ID': getCorporateIndividual.deartime_payerid, 'PRODUCT_NAME': prd.product_name}, 'fetchone')
    #                 last_payment_date = coverageDates['dset'][coverageDates['dcolname'].index('last_payment_on')]
    #                 renewal_date = last_payment_date + relativedelta(years=1)
    #                 age_on_last_payment_date = relativedelta(last_payment_date, self.member.dob)
    #                 age_on_renewal_date = relativedelta(renewal_date, self.member.dob)
    #             if prd.product_name != 'Medical':
    #                 getOptionsDict = deartimeDB.exec_SQL('getPremiumRate', {'PRODUCT_NAME': prd.product_name}, 'fetchone')
    #                 if getOptionsDict['dset']:
    #                     getPremiumRateOptions = json.loads(getOptionsDict['dset'][0])
    #                     getPremiumRateDict = getPremiumRateOptions['premium_rates']
    #                     for rate in getPremiumRateDict:
    #                         if renewal or old_lrd:
    #                             if rate[0] == age_on_last_payment_date.years:
    #                                 self.rate = rate[self.gender]
    #                             elif rate[0] == age_on_renewal_date.years:
    #                                 self.oldRate = rate[self.gender]
    #                         else:
    #                             if rate[0] == self.age:
    #                                 self.rate = rate[self.gender]
    #                                 self.oldRate = 0
    #             else:
    #                 getMedical = deartimeDB.exec_SQL('getMedicalPlans', {}, 'fetchone')
    #                 if getMedical['dset']:
    #                     getMedicalRateOptions = json.loads(getMedical['dset'][0])
    #                     getMedicalPlan = getMedicalRateOptions['plans']
    #                     for plan in getMedicalPlan:
    #                         if plan['deductible'] == self.coverage['Medical']:
    #                             getMedicalRateDict = plan['premium_rates']
    #                             for rate in getMedicalRateDict:
    #                                 if renewal or old_lrd:
    #                                     if rate[0] == age_on_last_payment_date.years:
    #                                         self.rate = rate[self.gender]
    #                                     elif rate[0] == age_on_renewal_date.years:
    #                                         self.oldRate = rate[self.gender]
    #                                 else:
    #                                     if rate[0] == self.age:
    #                                         self.rate = rate[self.gender]
    #                                         self.oldRate = 0

    #             if prd.product_name == 'Critical Illness':
    #                 self.lrd[prd.product_name]     = self.round_up((self.rate * self.coverage[prd.product_name] / 1000.00) * self.frequency)
    #                 self.nrd[prd.product_name]     = self.round_up((self.oldRate * self.coverage[prd.product_name] / 1000.00) * self.frequency)
    #             elif prd.product_name == 'Disability':
    #                 self.lrd[prd.product_name]     = self.round_up(((self.rate * self.coverage[prd.product_name] / 1000.00))* self.frequency)
    #                 self.nrd[prd.product_name]     = self.round_up(((self.oldRate * self.coverage[prd.product_name] / 1000.00))* self.frequency)
    #             elif prd.product_name == 'Medical':
    #                 self.lrd[prd.product_name]     = self.round_up(self.rate * self.frequency)
    #                 self.nrd[prd.product_name]     = self.round_up(self.oldRate * self.frequency)
    #             elif prd.product_name == 'Death':
    #                 self.lrd[prd.product_name]     = self.round_up((self.rate * self.coverage[prd.product_name] / 1000.00) * self.frequency)
    #                 self.nrd[prd.product_name]     = self.round_up((self.oldRate * self.coverage[prd.product_name] / 1000.00) * self.frequency)
    #             elif prd.product_name == 'Accident':
    #                 self.lrd[prd.product_name]     = self.round_up(((self.rate * self.coverage[prd.product_name] / 1000.00)) * self.frequency)
    #                 self.nrd[prd.product_name]     = self.round_up(((self.oldRate * self.coverage[prd.product_name] / 1000.00)) * self.frequency)

        
    # def calculate_without_loadings(self, DTmemberID, corporateID, memberProductMapping, deartimeDB, renewal = None, old_lrd = None):
    #     currentYear = datetime.datetime.now().year
    #     currentDate = datetime.datetime.now()
        
    #     getMemberIndividual = deartimeDB.exec_SQL('getIndividual', {'USER_ID': DTmemberID}, 'fetchone')
    #     getCorporateIndividual = CorporateProfile.objects.get(id=corporateID)
        
    #     self.calculate_fields(DTmemberID, corporateID, deartimeDB)
    #     if self.corporate.payment_mode == 'Monthly':
    #         self.frequency = 0.085
    #     if old_lrd:
    #         self.calculate_lrd(deartimeDB, None, old_lrd, getMemberIndividual, getCorporateIndividual, None, None, True)
    #     else:
    #         self.calculate_lrd(deartimeDB, None, None, getMemberIndividual, getCorporateIndividual, None, None, True)

    #     totalPremiumLRD = 0
    #     premium_due_date = datetime.datetime.strptime(self.corporate.payment_due_date, '%Y-%m-%d')
        
    #     for k, v in self.coverage.items():
    #         for prd in self.products:
    #             if prd.product_name == k and v != 0:
    #                 if renewal:
    #                     self.premium[prd.product_name] = round(self.nrd[prd.product_name], 2)
    #                 else:
    #                     totalPremiumLRD = totalPremiumLRD + self.lrd[prd.product_name]
    #                     self.premium[prd.product_name] = round(self.lrd[prd.product_name], 2)

    #     for k1, v1 in self.premium.items():
    #         for mpm in memberProductMapping:
    #             if mpm.deartime_coverageid and mpm.product.product_name.lower() == k1.lower():
    #                 updateCoveragesAmount = deartimeDB.exec_SQL('updateCoveragePaymentWithoutLoading', {'PAYMENT_WITHOUT_LOADING': v1, 'COVERAGE_ID': mpm.deartime_coverageid }, 'update')
                    
    #     return self.premium
        
class AgeCalculator():
    formats = ['%d/%m/%Y','%d-%m-%Y', '%Y/%m/%d', '%Y-%m-%d']

    def calculate_age(self, birthDate):
        current = datetime.datetime.today()
        self.birth_date = ''
        if isinstance(birthDate, str):
            for dateFormat in self.formats:
                try:
                    self.birth_date = datetime.datetime.strptime(birthDate, dateFormat)
                    formatTrue = True
                except:
                    pass
                        
        elif isinstance(birthDate, datetime.datetime):
            self.birth_date = birthDate

        if self.birth_date == '':
            self.age = -1
        else:
            self.age = current.year - self.birth_date.year - ((current.month, current.day) < (self.birth_date.month, self.birth_date.day))
        return self.age

    def calculate_age_with_memberid(self, DTmemberID):
        current = datetime.datetime.today()
        member = Member.objects.get(deartime_memberid=DTmemberID)
        self.birth_date = member.dob
        self.age = current.year - self.birth_date.year - ((current.month, current.day) < (self.birth_date.month, self.birth_date.day))
        return self.age

class CheckMemberConditions():
    overall_error = {} # change to {condition: boolean} when detected

    def check(self, coverages):
        self.check_coverage_limit(coverages)
        self.check_accident_death(coverages)
        return self.overall_error

    def check_coverage_limit(self, coverages: dict, *args):
        productKeyFields = [prd.product_name for prd in Product.objects.filter(is_active=True)]
        hasError = False
        limits = {
            'Death'             : 500000,
            'Disability'        : 350000,
            'Critical Illness'  : 350000,
            'Accident'          : 500000,
        }
        for prd in productKeyFields:
            if prd in limits:
                if int(coverages[prd]) > limits[prd]:
                    self.overall_error['coverage_limit'] = True
                    hasError = True
        if 'single' in args:
            return hasError
        
    # def check_accident_death(self, coverages, *args):
    #     hasError = False
    #     for prd in self.productKeyFields:
    #         if int(coverages['Accident']) != 0:
    #             if int(coverages['Death']) == 0 or int(coverages['Accident']) > int(coverages['Death']):
    #                 hasError = True
    #     if 'single' in args:
    #         return hasError

    # def check_has_coverage(self, coverages, *args):
    #     hasError = True
    #     for prd in self.productKeyFields:
    #         if coverages[prd] != None and int(coverages[prd]) != 0:
    #             hasError = False
    #     if 'single' in args:
    #         return hasError

    # def check_medical_plans(self, coverages, *args):
    #     hasError = False
    #     getMedicalObj   = GetMedicalPlans()
    #     isConnected     = getMedicalObj.connect()
    #     if not isConnected:
    #         return True
        
    #     medical_deductibles = getMedicalObj.getMedical()
    #     if coverages['Medical'] and int(coverages['Medical']) != 0:
    #         if not int(coverages['medical']) in medical_deductibles:
