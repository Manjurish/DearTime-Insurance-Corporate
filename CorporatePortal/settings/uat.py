from .base import *

DEBUG = False

ALLOWED_HOSTS = ['summer-dusk-uat-cpfo-w36v4ir4j635rwg.deartime.com', 'summer-dusk-w36v4ir4j635rwg.deartime.com']

SALT_HASH = 'AKIA3XIY5XGSAZMX7OFZ_'

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE'  : 'django.db.backends.mysql',
        'NAME'    : 'payorcorporate_uatdb_20230413',
        'USER'    : 'root',
        'PASSWORD': '@DeartimeAdmin123',
        'HOST'    : 'localhost',
        'PORT'    : '3306',
    }
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/
STATIC_URL  = 'static/'

MEDIA_URL  = 'media/'

RETRY_LIMIT = 5

HOST_ADDRESS = 'http://summer-dusk-w36v4ir4j635rwg.deartime.com'

HTTP_HOST_ADDRESS = 'http://summer-dusk-w36v4ir4j635rwg.deartime.com'

DT_USERNAME_DB      = 'vapor'
# DT_PASSWORD_DB      = 'CM6DgE1mUTEV5Bsr2VHZSN7pT9GPMM90v1WihYxQ'
DT_PASSWORD_DB      = 'hAnNZmj2ZT0UcmaQTENuWsI0ZXjqlwl0bP8YoSCC'
# DT_HOST_DB          = 'dtdevtest-db1.coairhi7msjn.ap-southeast-1.rds.amazonaws.com'
DT_HOST_DB          = 'dt-dev.cigziubn0gdn.ap-southeast-1.rds.amazonaws.com'
DT_PORT_DB          = '3306'
DT_DATABASE_NAME_DB = 'vapor'
PASSWORD_RESET_TIMEOUT_DAYS = 1440
PASSWORD_LINK_EXPIRED = 1440

PROD_SENANGPAY_URL = 'https://sandbox.senangpay.my/payment/'
PROD_SENANGPAY_SECRET_KEY = '5043-862'
PROD_SENANGPAY_MERCHANT_KEY = '995166623777013'
PROD_SENANGPAY_ORDER_QUERY_STATUS_URL = 'https://sandbox.senangpay.my/apiv1/query_order_status?' 

DT_CONTRACT_WEB_SERVICE = 'https://summer-dusk-v4ir4j459rwg.vapor-farm-b1.com/doc?'

LIMITED_LOGIN_ATTEMPT = 3

INVOICE_GENERATION_REFERENCE = '_DEV'

ENVIRONMENT_INDICATOR = 'DEV'