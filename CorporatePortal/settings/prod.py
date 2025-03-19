from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['ec2-13-251-86-52.ap-southeast-1.compute.amazonaws.com', 'insurance.deartime.com']

SALT_HASH = 'mnV8TyAfNn_'

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE'  : 'django.db.backends.mysql',
        'NAME'    : 'corporate_payor_prod',
        'USER'    : 'root',
        'PASSWORD': '@DeartimeAdmin123',
        'HOST'    : 'localhost',
        'PORT'    : '3306',
    }
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/
STATIC_URL  = '/corporate/static/'

MEDIA_URL  = '/corporate/media/'

RETRY_LIMIT = 5

HOST_ADDRESS = 'https://insurance.deartime.com/corporate'

HTTP_HOST_ADDRESS = 'http://ec2-13-251-86-52.ap-southeast-1.compute.amazonaws.com'

DT_USERNAME_DB      = 'vapor'
DT_PASSWORD_DB      = 'eexah6eiJohsh0deizadoo8Eehieyahquiech1oh'
DT_HOST_DB          = 'dtdevelopment-db.czczkb7mzfuk.ap-southeast-1.rds.amazonaws.com'
DT_PORT_DB          = '3306'
DT_DATABASE_NAME_DB = 'vapor'
PASSWORD_RESET_TIMEOUT_DAYS = 1440
PASSWORD_LINK_EXPIRED = 1440

PROD_SENANGPAY_URL = 'https://app.senangpay.my/payment/'
PROD_SENANGPAY_SECRET_KEY = '35751-493'
PROD_SENANGPAY_MERCHANT_KEY = '373165726457026'
PROD_SENANGPAY_ORDER_QUERY_STATUS_URL = 'https://app.senangpay.my/apiv1/query_order_status?'

DT_CONTRACT_WEB_SERVICE = 'https://insurance.deartime.com/doc?'

CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_AGE = 900
SESSION_SAVE_EVERY_REQUEST = True 
SESSION_COOKIE_SECURE = True

LIMITED_LOGIN_ATTEMPT = 3

INVOICE_GENERATION_REFERENCE = ''

ENVIRONMENT_INDICATOR = ''