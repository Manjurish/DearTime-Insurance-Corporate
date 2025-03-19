import logging
import os, hashlib, hmac, requests, json
from Portal.utils import *
from Portal.models import *
from django.template.loader import get_template
from num2words import num2words
from xhtml2pdf import pisa
from datetime import date


logging.basicConfig
logger = logging.getLogger(__name__)

log_filepath = os.path.join(settings.BASE_DIR, 'log/')
if datetime.datetime.now().weekday() == 0:
    log_filename = datetime.datetime.now().strftime("%Y_%m_%d") + "_CheckInvoicePaid.log"
else:
    monday = datetime.datetime.now() - timedelta(days = datetime.datetime.now().weekday())
    log_filename = monday.strftime("%Y_%m_%d") + "_CheckInvoicePaid.log"
fh = logging.FileHandler(log_filepath+log_filename)
logger.addHandler(fh)

def checkInvoicePaid():
    try:
        getPendingInvoice = Invoice.objects.filter(status='Payment In Progress')
        if getPendingInvoice:
            for inv in getPendingInvoice:
                try:
                    strToHash = settings.PROD_SENANGPAY_MERCHANT_KEY + settings.PROD_SENANGPAY_SECRET_KEY + inv.invoice_no.replace("/", "-")
                    hashResult = hmac.new(bytes(settings.PROD_SENANGPAY_SECRET_KEY, 'UTF-8'), bytes(strToHash, 'UTF-8'), hashlib.sha256)
                    sp_orderquery = settings.PROD_SENANGPAY_ORDER_QUERY_STATUS_URL + 'merchant_id=' + settings.PROD_SENANGPAY_MERCHANT_KEY + '&order_id=' + inv.invoice_no.replace("/", "-") + '&hash=' + hashResult.hexdigest()
                    getOrderDetails = requests.get(sp_orderquery)
                    jsonOrderDetails = json.loads(getOrderDetails.text)
                    for orders in jsonOrderDetails['data']:
                        invoiceNoReformat = inv.invoice_no.replace('/', '-')
                        if orders['product']['product_name'] == invoiceNoReformat:
                            if orders['payment_info']['status'] == 'paid':
                                deartimeDB  = DearTimeDbConn()
                                isConnected = deartimeDB.connect()
                                if not isConnected:
                                    logger.error("Connection Lost!")
                                else:
                                    getCorporateUserObj = CorporateProfile.objects.get(id=inv.company_id)
                                    memberList = []
                                    order       = {'UPDATED_DATE':str(datetime.datetime.now()), 'DEARTIME_ORDERID': inv.deartime_orderid }
                                    deartimeDB.exec_SQL('updateOrders', order, 'update')
                                    transaction = {'UPDATED_DATE':str(datetime.datetime.now()), 'DEARTIME_ORDERID': inv.deartime_orderid, 'TRANSACTION_REF': jsonOrderDetails['data'][0]['payment_info']['transaction_reference'] }
                                    deartimeDB.exec_SQL('updateTransactions', transaction, 'update')
                                    calculator = PremiumCalculator()
                                    getInvoicePaidDatetime = deartimeDB.exec_SQL('getInvoicePaidDatetime', {'ORDER_ID': inv.deartime_orderid}, 'fetchone')
                                    orderObj = Order.objects.filter(invoice_id=inv.id)
                                    # Current date
                                    currentDate = GenericLibraries().currentDateTesting(getCorporateUserObj.id, True)
                                    if orderObj:
                                        for ord in orderObj:
                                            member = Member.objects.get(id=ord.member_id)
                                            memberADPremium = PremiumAdjustment.objects.filter(member_id=member.id)
                                            if not memberADPremium:
                                                getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                                getUnderwritingID = deartimeDB.exec_SQL('getUnderwriting', {'INDIVIDUAL_ID': getIndividualID['dset'][0]}, 'fetchone')
                                                # getMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False, is_renewal = member.renew)
                                                
                                                if member.renew:                                                        
                                                        
                                                    status_dict = {
                                                        'grace-unpaid': 'active',
                                                        'grace-increase-unpaid': 'active-increased'
                                                    }
                                                    status_dict2 = {
                                                        'active': 'fulfilled',
                                                        'active-increased': 'fulfilled-increased'
                                                    }
                                                    
                                                    existingMemberCoverages = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False, is_renewal = False, deartime_coverageid__isnull=False)
                                                    if existingMemberCoverages:
                                                        for currentCoverages in existingMemberCoverages:
                                                            getCoverage = deartimeDB.exec_SQL('getCoverageFromMPM', {'COVERAGE_ID': currentCoverages.deartime_coverageid}, 'fetchall')
                                                            for cvg in getCoverage['dset']:
                                                                for old_status, fulfilled_status in status_dict2.items():
                                                                    old_coverages = {'NEW_STATUS': fulfilled_status, 'COVERAGE_ID': cvg[0], 'ORIGINAL_STATUS': old_status}
                                                                    deartimeDB.exec_SQL('updateCoveragesFulfilled', old_coverages, 'update')
                                                                            
                                                    oldMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False, is_renewal = False)
                                                    if oldMemberProductMapping:
                                                        for oldMPM in oldMemberProductMapping:
                                                            oldMPM.is_terminated = True
                                                            oldMPM.save()   
                                                    newMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False, is_renewal = True)
                                                    if newMemberProductMapping:
                                                        for newMPM in newMemberProductMapping:
                                                            newMPM.is_renewal = False
                                                            newMPM.save()
                                                            
                                                else:
                                                    getIndividualID = deartimeDB.exec_SQL('getIndividual', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                                    getUnderwritingID = deartimeDB.exec_SQL('getUnderwriting', {'INDIVIDUAL_ID': getIndividualID['dset'][0]}, 'fetchone')
                                                    status_dict = {
                                                        'unpaid': 'active',
                                                        'increase-unpaid': 'active-increased'
                                                    }
                                                
                                                getCoverage = deartimeDB.exec_SQL('getCoverageFromOrder', {'ORDER_ID': inv.deartime_orderid, 'INDIVIDUAL_ID':getIndividualID['dset'][0]}, 'fetchall')
                                                for cvg in getCoverage['dset']:
                                                    if member.renew:
                                                        coverage_dates = deartimeDB.exec_SQL('getCoveragesDatesv2', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID': getCorporateUserObj.deartime_payerid, 'PRODUCT_NAME': str(cvg[1])}, 'fetchone')
                                                    else:
                                                        coverage_dates = deartimeDB.exec_SQL('getCoveragesDates', {'OWNER_ID': getIndividualID['dset'][0], 'PAYER_ID': getCorporateUserObj.deartime_payerid, 'PRODUCT_NAME':str(cvg[1])}, 'fetchone')
                                                    last_payment_on = str(inv.created_datetime)
                                                    if coverage_dates['dset']:
                                                        first_payment_on = coverage_dates['dset'][coverage_dates['dcolname'].index('first_payment_on')]
                                                    else:
                                                        first_payment_on = inv.created_datetime
                                                    if getCorporateUserObj.payment_mode == 'Monthly':
                                                        first_to_last_payment_difference = relativedelta(inv.created_datetime, first_payment_on)
                                                        if first_to_last_payment_difference.months < 1:
                                                            next_payment_on = first_payment_on + relativedelta(months=1)
                                                        else:
                                                            next_payment_on = first_payment_on + relativedelta(months=first_to_last_payment_difference.months + 1)
                                                    else:
                                                        first_to_last_payment_difference = relativedelta(inv.created_datetime, first_payment_on)
                                                        if first_to_last_payment_difference.years < 1:
                                                            next_payment_on = first_payment_on + relativedelta(years=1)
                                                        else:
                                                            next_payment_on = first_payment_on + relativedelta(years=first_to_last_payment_difference.years + 1)
                                                    paymentDueDate = datetime.datetime.strptime(getCorporateUserObj.payment_due_date, '%Y-%m-%d')
                                                    payor_next_payment_date = paymentDueDate
                                                    for status, new_status in status_dict.items():
                                                        if member.renew:
                                                            if (currentDate.day < paymentDueDate.day) and (currentDate.month <=  paymentDueDate.month):
                                                                payor_next_payment_date = paymentDueDate + relativedelta(years=1)
                                                            coverages = {'FIRST_PAYMENT_DATE': first_payment_on, 'PAYMENT_DUEDATE': str(next_payment_on), 'UPDATED_DATE': str(datetime.datetime.now()), 'PAYOR_NEXT_PAYMENT_DATE': payor_next_payment_date, 'INVOICE_CREATED_DATE': str(inv.created_datetime), 'COVERAGE_ID': cvg[0], 'UW_ID': getUnderwritingID['dset'][0], 'ORIGINAL_STATUS': status, 'NEW_STATUS': new_status}                                                 
                                                            deartimeDB.exec_SQL('updateRenewalCoveragesStatus', coverages, 'update')
                                                        else:
                                                            coverages     = {'FIRST_PAYMENT_ON': str(first_payment_on), 'NEXT_PAYMENT_ON': str(next_payment_on), 'LAST_PAYMENT_ON':str(last_payment_on), 'PAYOR_NEXT_PAYMENT_DATE': payor_next_payment_date, 'INVOICE_CREATED_DATE': str(inv.created_datetime), 'UPDATED_DATE': str(datetime.datetime.now()), 'COVERAGE_ID': cvg[0], 'UW_ID': getUnderwritingID['dset'][0], 'ORIGINAL_STATUS': status, 'NEW_STATUS': new_status}
                                                            deartimeDB.exec_SQL('updateCoveragesStatus', coverages, 'update')

                                                getLatestActionID    = deartimeDB.exec_SQL('selectMaxIDActions', {}, 'fetchone')           
                                                nextLatestActionID   = getLatestActionID['dset'][0] + 1
                                                actionRefNo          = 'AC' + str(nextLatestActionID).zfill(6)
                                                action = {}
                                                coverageDict = {}
                                                getMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False)
                                                for mpg in getMapping:
                                                    if mpg.coverage_amount != 0:
                                                        action['new_'+Product.objects.get(id=mpg.product_id).product_name.lower()] = int(mpg.coverage_amount)
                                                        coverageDict[Product.objects.get(id=mpg.product_id).product_name] = int(mpg.coverage_amount)

                                                if getCorporateUserObj.payment_mode == 'Monthly':
                                                    action['new_payment_term'] = 'monthly'
                                                else:
                                                    action['new_payment_term'] = 'annually'

                                                if member.renew:
                                                    dataDictsAC          = (str(uuid.uuid4()), actionRefNo, member.deartime_memberid, 'Plan Change', 'PlanChange', json.dumps(action), 'executed', str(datetime.datetime.now()), 'User', CorporateProfile.objects.get(id=member.corporate_id).deartime_payerid,  str(datetime.datetime.now()), str(datetime.datetime.now()))
                                                else:
                                                    dataDictsAC          = (str(uuid.uuid4()), actionRefNo, member.deartime_memberid, 'Member Addition', 'newMember', json.dumps(action), 'executed', str(datetime.datetime.now()), 'User', CorporateProfile.objects.get(id=member.corporate_id).deartime_payerid,  str(datetime.datetime.now()), str(datetime.datetime.now()))
                                                
                                                getNewActionID       = deartimeDB.exec_SQL('insertActions', dataDictsAC, 'insert')
                                                for mpg2 in getMapping:
                                                    if mpg2.coverage_amount != 0:
                                                        dataDictsACCOV       = (getNewActionID['lastID'], mpg2.deartime_coverageid, str(datetime.datetime.now()), str(datetime.datetime.now()))
                                                        getNewActionCoverID  = deartimeDB.exec_SQL('insertActionCoverage', dataDictsACCOV, 'insert')
                                                        
                                                getMemberProductMapping = MemberProductMapping.objects.filter(member_id=member.id, is_terminated=False, is_renewal = False, deartime_coverageid__isnull=False)
                                                paymentsWithoutLoadingDict = calculator.calculate_premium(member.deartime_memberid, getCorporateUserObj.id, 'total', getMemberProductMapping, deartimeDB, member.renew, member.renew, None, True)                                                    
                                                member.renew = False
                                                member.paid = True
                                                member.tentative_premium = ord.amount
                                                member.true_premium = ord.true_amount
                                            
                                            else:
                                                for memberAD in memberADPremium:
                                                    memberAD.paid = True
                                                    memberAD.save()
                                            
                                            member.status = 'Active'
                                            member.save()

                                            if not memberADPremium:
                                                #getMemberObj            = Member.objects.get(id=orders.member.id)
                                                getIndividualID         = deartimeDB.exec_SQL('getIndividual', {'USER_ID': member.deartime_memberid}, 'fetchone')
                                                getSelfThanksGivings    = deartimeDB.exec_SQL('getThanksgivingsSelfType', {'INDIVIDUAL_ID': getIndividualID['dset'][0]}, 'fetchone')
                                                getCharityThanksGivings = deartimeDB.exec_SQL('getThanksgivingsCharityType', {'INDIVIDUAL_ID': getIndividualID['dset'][0]}, 'fetchone')
                                                getReferralThanksGivings = deartimeDB.exec_SQL('getReferralThanksGiving', {'INDIVIDUAL_ID': getIndividualID['dset'][0]}, 'fetchone')
                                                getCoveragesID = deartimeDB.exec_SQL('getThanksgivingCoverageID', {'INDIVIDUAL_ID': getIndividualID['dset'][0]}, 'fetchall')
                                                if getSelfThanksGivings['dset']:
                                                    thanksgivingsAmount     = round(float(ord.true_amount) * (getSelfThanksGivings['dset'][1] / 10 / 100), 2)
                                                    getLatestCreditID       = deartimeDB.exec_SQL('selectMaxIDCredits', {}, 'fetchone')
                                                    nextLatestCreditID      = getLatestCreditID['dset'][0] + 1
                                                    creditRefNo             = 'CR' + str(nextLatestCreditID).zfill(6)
                                                    dataDictsCR_POS         = (str(uuid.uuid4()), creditRefNo, inv.deartime_orderid, member.deartime_memberid, member.deartime_memberid, thanksgivingsAmount, 'App\Thanksgiving', getSelfThanksGivings['dset'][0], str(datetime.datetime.now()), str(datetime.datetime.now()))
                                                    getNewCreditsID_POS     = deartimeDB.exec_SQL('insertCredits', dataDictsCR_POS, 'insert')
                                                    creditRefNo             = 'CR' + str(getNewCreditsID_POS['lastID'] + 1).zfill(6)
                                                    dataDictsCR_NEG         = (str(uuid.uuid4()), creditRefNo, inv.deartime_orderid, member.deartime_memberid, member.deartime_memberid, -thanksgivingsAmount, 'App\Thanksgiving', getSelfThanksGivings['dset'][0], str(datetime.datetime.now()), str(datetime.datetime.now()))
                                                    getNewCreditsID_NEG     = deartimeDB.exec_SQL('insertCredits', dataDictsCR_NEG, 'insert')
                                                if getCharityThanksGivings['dset']:
                                                    if getCharityThanksGivings['dset'][1] != 0:
                                                        thanksgivingsAmount     = round(float(ord.true_amount) * (getCharityThanksGivings['dset'][1] / 10 / 100), 2)
                                                        getLatestCreditID       = deartimeDB.exec_SQL('selectMaxIDCredits', {}, 'fetchone')
                                                        nextLatestCreditID      = getLatestCreditID['dset'][0] + 1
                                                        creditRefNo             = 'CR' + str(nextLatestCreditID).zfill(6)
                                                        dataDictsCR_CH          = (str(uuid.uuid4()), creditRefNo, inv.deartime_orderid, None, member.deartime_memberid, thanksgivingsAmount, 'App\Thanksgiving', getCharityThanksGivings['dset'][0], str(datetime.datetime.now()), str(datetime.datetime.now()))
                                                        getNewCreditsID_CH      = deartimeDB.exec_SQL('insertCredits', dataDictsCR_CH, 'insert')
                                                        insertSPO(getCharityThanksGivings, inv, member.deartime_memberid)
                                                if getReferralThanksGivings['dset']:
                                                    if getReferralThanksGivings['dset'][0] != 0:
                                                        thanksgivingsAmount     = round(float(ord.true_amount) * (getReferralThanksGivings['dset'][0] / 10 / 100), 2)
                                                        getReferrer             = deartimeDB.exec_SQL('getReferrerFromUser', {'USER_ID' : member.deartime_memberid}, 'fetchone')
                                                        dataDictsReferral       = (getReferrer['dset'][1], member.deartime_memberid, getReferrer['dset'][0], member.name.upper(), thanksgivingsAmount, getReferralThanksGivings['dset'][0], 'ON HOLD', inv.deartime_orderid, str(datetime.datetime.now().strftime("%B")), str(datetime.datetime.now().year), '0000-00-00', str(datetime.datetime.now()), str(datetime.datetime.now()), str(uuid.uuid4()))
                                                        getNewReferral          = deartimeDB.exec_SQL('insertReferral', dataDictsReferral, 'insert')
                                                insertThanksgiving(getSelfThanksGivings, getCharityThanksGivings, getCoveragesID)
                                
                                    inv.senangpay_refno = orders['payment_info']['transaction_reference']
                                    inv.status = 'Paid'
                                    inv.payment_date = datetime.datetime.strptime(str(date.fromtimestamp(int(orders['payment_info']['transaction_date']))), "%Y-%m-%d")
                                    getUserCorporateRefNo = deartimeDB.exec_SQL('getUserRefNo', {'USER_ID': getCorporateUserObj.deartime_payerid}, 'fetchone')
                                    receipt = GenerateReceiptPDF(inv, orderObj, getInvoicePaidDatetime['dset'][0], getUserCorporateRefNo['dset'][0], deartimeDB)
                                    inv.receipt_no = receipt
                                    inv.save()
                                    deartimeDB.close()
                            elif orders['payment_info']['status'] == 'failed':
                                deartimeDB  = DearTimeDbConn()
                                isConnected = deartimeDB.connect()
                                # invoiceNo = orders['product']['product_name']
                                # try:
                                #     getUserInvoiceObj = Invoice.objects.get(invoice_no=invoiceNo)
                                # except Exception as e:
                                #     logger.error(str(e))
                                # orderID = getUserInvoiceObj.deartime_orderid
                                getOrdRetr = deartimeDB.exec_SQL('getOrdersRetries', {'ORDER_ID': inv.deartime_orderid}, 'fetchone')
                                retriesNum = getOrdRetr['dset'][0]
                                retriesNum = int(retriesNum)
                                if retriesNum > 0:
                                    retriesNum -= 1
                                    updateOrderRetries = deartimeDB.exec_SQL('updateOrdersRetries', {'RETRY_NUM':retriesNum, 'ORDER_ID': inv.deartime_orderid}, 'update')
                                # else:
                                #     logger.error(str(ex) + "|" + str(CorporateProfile.objects.get(id=inv.company_id)))                
                except Exception as ex:
                    logger.error(str(ex) + "|" + str(CorporateProfile.objects.get(id=inv.company_id)))
                    
    except Exception as ex:
        logger.error(str(ex))

def GenerateReceiptPDF(invoice, memberid_list, invoicePaidDatetime, corpRefNo, deartimeDB):
    getUserCorporateObj = CorporateProfile.objects.get(id=invoice.company_id)
    generateReceiptNo   = 'R' + str(invoicePaidDatetime.year) + str(invoicePaidDatetime.month).zfill(2) + '/' + str(get_next_value(sequence_name="receipt")).zfill(5)
    total               = 0

    memberList = []

    for memberID in memberid_list:
        # getMember = Member.objects.get(deartime_memberid=memberID)
        getMember = Member.objects.get(id=memberID.member_id)
        coverageDict = {}
        getMapping = PackageProductMapping.objects.filter(package_id=getMember.package_id)
        for mpg in getMapping:
            if mpg.coverage_amount != 0:
                coverageDict[Product.objects.get(id=mpg.product_id).product_name] = mpg.coverage_amount

        notificationCoverageStr = ''
        for key, value in coverageDict.items():
            notificationCoverageStr = notificationCoverageStr + ':' + key + ':' + str(value) + '\n'

        dataDict = {
            'data' : 'policies_page',
            'command' : 'next_page',
            'translate_data' : {
                'trx' : invoice.senangpay_refno,
                'user' : getUserCorporateObj.company_name,
                'amount' : str(getMember.tentative_premium),
                'coverages' : notificationCoverageStr
            }
        }
        dataNF = (str(uuid.uuid4()), getMember.deartime_memberid, 'mobile.we_got_you_covered', 'mobile.paid_order_notification', 'mobile.paid_order_notification', json.dumps(dataDict), 0, 0, 1, str(datetime.datetime.now()), str(datetime.datetime.now()))
        notification = deartimeDB.exec_SQL('insertNotification', dataNF, 'insert')

        total += getMember.tentative_premium
        memberList.append(getMember)

    totalPayables = "{:.2f}".format(total)
    totalPayablesWord = num2words(totalPayables, to='currency').title().replace('Euro', "")
    if float(totalPayables).is_integer():
        totalPayablesWord = totalPayablesWord.split(',')[0]
    totalPayablesWord += " Only"

    rowCount = 10
    paginator = Paginator(memberList, rowCount)

    file = render_to_pdf(getUserCorporateObj.company_name, generateReceiptNo, 'InvoiceAndPayment/Receipt.html',
        {
            'pagesize'           : 'A4',
            'image_url'          : settings.STATICFILES_DIRS[0].replace("\\","/") + '/portal/img/deartime-logo-inverted-color.png',
            'company'            : getUserCorporateObj,
            'tables'             : paginator,
            'total_payables'     : totalPayables,
            'total_payables_text': totalPayablesWord,
            'payor_ref'          : corpRefNo,
            'receipt_no'         : generateReceiptNo,
            'receipt_date'       : datetime.datetime.strftime(invoicePaidDatetime, '%d %B %Y'), #invoice paid datetime,
            'payment_for'        : invoice.invoice_no,
            'flag'               : 'receipt'
        })
    return generateReceiptNo

def render_to_pdf(companyName, receiptNo, template_src, context_dict):
    template = get_template(template_src)
    html  = template.render(context_dict)
    path = companyName + "/Receipt"
    if not os.path.exists(settings.MEDIA_ROOT.replace("\\", "/") + "/" + path):
        os.mkdir(settings.MEDIA_ROOT.replace("\\", "/") + "/" + path)
    file = receiptNo.replace("/", "_") + ".pdf"
    f = open(settings.MEDIA_ROOT.replace("\\", "/")+"/"+path+"/"+file, 'wb')
    pdf_status  = pisa.CreatePDF(html, dest=f)
    f.close()
    
    if pdf_status.err:
        return HttpResponse('Some errors were encountered <pre>' + html + '</pre>')
    return path+"/"+file

def insertThanksgiving(getSelfThanksGivings, getCharityThanksGivings, getCoveragesID):
    deartimeDB = DearTimeDbConn()
    isConnected = deartimeDB.connect()
    
    clean_coverages_id = [tupleValue[0] for tupleValue in getCoveragesID.get('dset', []) if isinstance(tupleValue, tuple)]
    
    charityID = getCharityThanksGivings['dset'][0] if getCharityThanksGivings['dset'] else None
    selfID = getSelfThanksGivings['dset'][0] if getSelfThanksGivings['dset'] else None
    # if getCharityThanksGivings['dset'] and getSelfThanksGivings['dset']:
    # charityID = getCharityThanksGivings['dset'][0]
    # selfID = getSelfThanksGivings['dset'][0]

    dictSelf = {covID: selfID for covID in clean_coverages_id}
    dictChar = {covID: charityID for covID in clean_coverages_id}
    
    for key, value in dictSelf.items():
        if value is not None:
            dataDict = (key, value) 
            print(dataDict)
            insertSelfCovThanks = deartimeDB.exec_SQL('insertCoverThanksgive', dataDict, 'insert')

    for key, value in dictChar.items():
        if value is not None:
            dataDict = (key, value)
            print(dataDict)
            insertCharCovThanks = deartimeDB.exec_SQL('insertCoverThanksgive', dataDict, 'insert')				

def insertSPO(getCharityThanksGivings, inv, userID):
    deartimeDB = DearTimeDbConn()
    isConnected = deartimeDB.connect()

    getOrdTrAmt = deartimeDB.exec_SQL('getOrdersDetails', {'ORDER_ID': inv.deartime_orderid}, 'fetchone')
    getTransID = deartimeDB.exec_SQL('getTransactDetails', {'ORDER_ID': inv.deartime_orderid}, 'fetchone')

    chariPerc = getCharityThanksGivings['dset'][1]
    truAmt = getOrdTrAmt['dset'][1]
    orderID = getOrdTrAmt['dset'][2]
    transactID =  getTransID['dset'][0]

    charitFund = (truAmt * chariPerc) / 100

    dataNF = (str(uuid.uuid4()), userID, orderID, transactID, truAmt, chariPerc, charitFund,  str(datetime.datetime.now()), str(datetime.datetime.now()))
    insertSPO = deartimeDB.exec_SQL('insertSpoCharityFunds', dataNF, 'insert')
    print("somthing")