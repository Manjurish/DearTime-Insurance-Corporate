from .base import *

DEBUG = False

ALLOWED_HOSTS = ['ec2-13-251-86-52.ap-southeast-1.compute.amazonaws.com', 'summer-dusk-uat-cpfo-w36v4ir4j635rwg.deartime.com']

SALT_HASH = 'AKIA3XIY5XGSAZMX7OFZ_'

#Database
#https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE'  : 'django.db.backends.mysql',
        'NAME'    : 'payorcorporate',
        'USER'    : 'root',
        'PASSWORD': '@BoitAdmin123',
        'HOST'    : 'localhost',
        'PORT'    : '3306',
    }
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/
STATIC_URL  = 'static/'

MEDIA_URL  = 'media/'

RETRY_LIMIT = 5

HOST_ADDRESS = 'https://summer-dusk-uat-cpfo-w36v4ir4j635rwg.deartime.com'

HTTP_HOST_ADDRESS = 'https://summer-dusk-uat-cpfo-w36v4ir4j635rwg.deartime.com'

DT_USERNAME_DB      = 'vapor'
# DT_PASSWORD_DB      = 'TlcRVpimO8C0Sa5rid3rILFQWT2DG7gxn6MVS1Pf'
DT_PASSWORD_DB      = 'hAnNZmj2ZT0UcmaQTENuWsI0ZXjqlwl0bP8YoSCC'
DT_HOST_DB          = 'dt-dev.cigziubn0gdn.ap-southeast-1.rds.amazonaws.com'
DT_PORT_DB          = '3306'
DT_DATABASE_NAME_DB = 'vapor'
PASSWORD_RESET_TIMEOUT_DAYS = 1440
PASSWORD_LINK_EXPIRED = 1440

PROD_SENANGPAY_URL = 'https://sandbox.senangpay.my/payment/'
PROD_SENANGPAY_SECRET_KEY = '4850-836'
PROD_SENANGPAY_MERCHANT_KEY = '734165884262855'
PROD_SENANGPAY_ORDER_QUERY_STATUS_URL = 'https://sandbox.senangpay.my/apiv1/query_order_status?'
# SANDBOX_SENANGPAY = 'https://sandbox.senangpay.my/payment/'
# SANDBOX_SENANGPAY_SECRET_KEY = '4850-836'
# SANDBOX_SENANGPAY_MERCHANT_KEY = '734165884262855'
# SANDBOX_SENANGPAY_ORDER_QUERY_STATUS_URL = 'https://sandbox.senangpay.my/apiv1/query_order_status?'

DT_CONTRACT_WEB_SERVICE = 'https://summer-dusk-v4ir4j459rwg.vapor-farm-b1.com/doc?'

CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_AGE = 9000
SESSION_SAVE_EVERY_REQUEST = True 
SESSION_COOKIE_SECURE = True

LIMITED_LOGIN_ATTEMPT = 100

INVOICE_GENERATION_REFERENCE = '_UAT'

ENVIRONMENT_INDICATOR = 'UAT'
