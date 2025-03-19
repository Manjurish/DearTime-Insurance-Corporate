from django.db import models
from django.contrib.auth.models import User, AbstractUser, BaseUserManager

# Create your models here.
class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)

class CorporateUser(AbstractUser):
    username = models.CharField(
        max_length=150,
        unique=False,
    )

    objects = UserManager()

    def _str_(self):
        return self.email

class CorporateProfile(models.Model):
    class Meta:
        db_table            = 'CorporateProfile'
        verbose_name_plural = 'Corporate Profile'
    
    user             = models.ForeignKey(CorporateUser, on_delete=models.CASCADE)
    deartime_payerid = models.IntegerField(blank=True, null=True)
    company_name     = models.CharField(max_length=100, blank=False, null=False)
    val_company_name = models.CharField(max_length=100, blank=False, null=False)
    registration_no  = models.CharField(max_length=100, blank=False, null=False)
    val_registration_no = models.CharField(max_length=100, blank=False, null=False)
    contact1         = models.CharField(max_length=25, blank=True, null=True)
    contact2         = models.CharField(max_length=25, blank=True, null=True)
    email_address    = models.CharField(max_length=100, blank=False, null=False)
    address_line1    = models.CharField(max_length=255, blank=True, null=True)
    address_line2    = models.CharField(max_length=255, blank=True, null=True)
    address_line3    = models.CharField(max_length=255, blank=True, null=True)
    state            = models.CharField(max_length=25, blank=True, null=True)
    city             = models.CharField(max_length=25, blank=True, null=True)
    postcode         = models.CharField(max_length=25, blank=True, null=True)
    payment_due_date = models.CharField(max_length=25, blank=True, null=True)
    submitted        = models.BooleanField(default=False)
    verified         = models.BooleanField(default=False)
    status           = models.CharField(max_length=200, null=False, blank=False)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    updated_datetime = models.DateTimeField(blank=True, null=True)
    rejected         = models.BooleanField(default=False)
    remarks          = models.CharField(max_length=100, blank=True, null=True)
    payment_mode     = models.CharField(max_length=20, blank=True, null=True)
    deferred         = models.BooleanField(default=False)
    corporate_campaign_code    = models.CharField(max_length=100, blank=True, null=True)
    
class CorporateProfileFormAttachment(models.Model):
    class Meta:
        db_table            = 'CorporateProfileFormAttachment'
        verbose_name_plural = 'Corporate Profile Form Attachment'
    
    company         = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE, blank=False, null=False)
    form_code       = models.CharField(max_length=30, blank=False, null=False)
    attachment_type = models.CharField(max_length=30, blank=False, null=False)
    attachment      = models.TextField(null=True, blank=True)

class RelationshipType(models.Model):
    class Meta:
        db_table            = 'RelationshipType'
        verbose_name_plural = 'Relationship Type'
    
    relationship_name = models.CharField(max_length=100, blank=False, null=False)
    is_active         = models.BooleanField(default=True)
    created_by        = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime  = models.DateTimeField(auto_now_add=True)
    updated_by        = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    updated_datetime  = models.DateTimeField(blank=True, null=True)

class CompanyRelationship(models.Model):
    class Meta:
        db_table            = 'CompanyRelationship'
        verbose_name_plural = 'CompanyRelationship'
    
    company           = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE, blank=False, null=False)
    relationship_type = models.ForeignKey(RelationshipType, on_delete=models.CASCADE, blank=False, null=False)
    is_voided         = models.BooleanField(default=False)
    created_by        = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime  = models.DateTimeField(auto_now_add=True)
    voided_by         = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    void_datetime     = models.DateTimeField(blank=True, null=True)
    def get_relationship_name(self):
        return self.relationship_type.relationship_name

class EntityType(models.Model):
    class Meta:
        db_table            = 'EntityType'
        verbose_name_plural = 'Entity Type'

    entity_name         = models.CharField(max_length=100, blank=False, null=False)
    is_active           = models.BooleanField(default=True)
    created_by          = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime    = models.DateTimeField(auto_now=True)
    updated_by          = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    updated_datetime    = models.DateTimeField(blank=True, null=True)

class CorporateProfileFormAttachment(models.Model):
    class Meta:
        db_table            = 'CorporateProfileFormAttachment'
        verbose_name_plural = 'Corporate Profile Form Attachment'
    
    company         = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE, blank=False, null=False)
    form_code       = models.CharField(max_length=30, blank=False, null=False)
    attachment_type = models.CharField(max_length=30, blank=False, null=False)
    attachment      = models.TextField(null=True, blank=True)
    entity_type     = models.ForeignKey(EntityType, on_delete=models.CASCADE, blank=True, null=True)

class CompanyFormType(models.Model):
    # UPLOAD_TYPE_CHOICES = (("single","Single Upload"),("multiple","Multiple Upload"))

    class Meta:
        db_table            = 'CompanyFormType'
        verbose_name_plural = 'Company Form Type'
    
    form_type_name   = models.CharField(max_length=125, blank=False, null=False)
    description      = models.CharField(max_length=25, blank=True, null=False)
    entity_type      = models.ForeignKey(EntityType, on_delete=models.CASCADE, blank=True, null=True)
    # upload_type      = models.CharField(max_length=25, choices=UPLOAD_TYPE_CHOICES, blank=False, null=False)
    is_active        = models.BooleanField(default=True)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    updated_datetime = models.DateTimeField(blank=True, null=True)
    form_type_id     = models.CharField(max_length=30, blank=True, null=True)

class CompanyFormRelationshipMapping(models.Model):
    class Meta:
        db_table            = 'CompanyFormRelationshipMapping'
        verbose_name_plural = 'Company Form Relationship Mapping'
    
    company_relationship = models.ForeignKey(CompanyRelationship, on_delete=models.CASCADE, blank=False, null=False)
    company_form_type    = models.ForeignKey(CompanyFormType, on_delete=models.CASCADE, blank=False, null=False)
    is_voided            = models.BooleanField(default=False)
    created_by           = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime     = models.DateTimeField(auto_now_add=True)
    voided_by            = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    void_datetime        = models.DateTimeField(blank=True, null=True)

class Product(models.Model):
    class Meta:
        db_table            = 'Product'
        verbose_name_plural = 'Product'
    
    product_name     = models.CharField(max_length=150, blank=False, null=False)
    is_active        = models.BooleanField(default=True)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    updated_datetime = models.DateTimeField(blank=True, null=True)
class SaveUppercase(models.CharField):
    def __init__(self, *args, **kwargs):
        super(SaveUppercase, self).__init__(*args, **kwargs)

    def get_prep_value(self, value):
        return str(value).upper()
class Package(models.Model):
    class Meta:
        db_table            = 'Package'
        verbose_name_plural = 'Package'
    
    package_name     = SaveUppercase(max_length=150, blank=False, null=False)
    description      = models.CharField(max_length=350, blank=True, null=True)
    is_active        = models.BooleanField(default=True)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")
    updated_datetime = models.DateTimeField(blank=True, null=True)
    under_campaign   = models.CharField(max_length=100, blank=True, null=True)

class PackageProductMapping(models.Model):
    class Meta:
        db_table            = 'PackageProductMapping'
        verbose_name_plural = 'Package Product Mapping'
    
    package          = models.ForeignKey(Package, on_delete=models.CASCADE, blank=False, null=False)
    product          = models.ForeignKey(Product, on_delete=models.CASCADE, blank=False, null=False)
    coverage_amount  = models.IntegerField(null=False, blank=False)
    is_active        = models.BooleanField(default=True)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=True, null=True, related_name="%(class)s_updated_by_user")


class Member(models.Model):
    class Meta:
        db_table            = 'Member'
        verbose_name_plural = 'Premium Holder'
    
    corporate         = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE)
    batch_no          = models.CharField(max_length=50, blank=True, null=True)
    employment_no     = models.CharField(max_length=50, blank=False, null=False)
    name              = models.CharField(max_length=100, blank=False, null=False)
    email_address     = models.CharField(max_length=100, blank=False, null=False)
    mobile_no         = models.CharField(max_length=100, blank=False, null=False)
    nationality       = models.CharField(max_length=25, blank=False, null=False)
    mykad             = models.CharField(max_length=100, blank=True, null=True)
    passport          = models.CharField(max_length=25, blank=True, null=True)
    dob               = models.DateField(blank=False, null=False)
    gender            = models.CharField(max_length=10, blank=False, null=False)
    package           = models.ForeignKey(Package, on_delete=models.CASCADE)
    tentative_premium = models.DecimalField(default=0.00, blank=True, null=True, decimal_places=2, max_digits=50)
    campaign_code     = models.CharField(max_length=100, blank=True, null=True)
    submitted         = models.BooleanField(default=False)
    medical_survey    = models.BooleanField(default=False)
    paid              = models.BooleanField(default=False)
    renew             = models.BooleanField(default=False)
    status            = models.CharField(max_length=45, blank=True, null=True)
    void              = models.BooleanField(default=False)
    renew             = models.BooleanField(default=False)
    deartime_memberid = models.IntegerField(blank=True, null=True)
    last_reminder     = models.DateTimeField(null=True, blank=True)
    rejected          = models.BooleanField(default=False)
    created_datetime  = models.DateTimeField(auto_now_add=True)
    sendinvitation_datetime = models.DateTimeField(blank=True,null=True)
    is_existing       = models.BooleanField(default=False)
    reminder_count    = models.IntegerField( blank=True, null=True)
    invoice_reminder_count    = models.IntegerField( blank=True, null=True)
    generated_invoice = models.BooleanField(default=False)
    rejected_reason   = models.CharField(max_length=100, blank=True, null=True)
    si_waitinglist    = models.BooleanField(default=False)
    is_deleted        = models.BooleanField(default=False)
    siwaiting_email   = models.BooleanField(default=False)
    quotation_premium = models.DecimalField(default=0.00, blank=True, null=True, decimal_places=2, max_digits=50)
    true_premium      = models.DecimalField(default=0.00, blank=True, null=True, decimal_places=2, max_digits=50)
    updated_datetime  = models.DateTimeField(null=True, blank=True)
    read_datetime     = models.DateTimeField(null=True, blank=True)

class MessagingQueue(models.Model):
    class Meta:
        db_table = 'MessageQueue'
    
    email_address    = models.CharField(max_length=100, null=True, blank=True)
    message_content  = models.TextField()
    module           = models.CharField(max_length=50)
    status           = models.BooleanField(default=False)
    request_datetime = models.DateTimeField(auto_now_add=True)
    send_datetime    = models.DateTimeField(null=True, blank=True)
    retry            = models.IntegerField(default=0, null=True, blank=True)
    void             = models.BooleanField(default=False)
    
# class Underwriting(models.Model):
#     class Meta:
#         db_table            = 'Underwriting'
#         verbose_name_plural = 'Underwriting'
    
#     member     = models.ForeignKey(Member, on_delete=models.CASCADE)
#     death      = models.BooleanField(default=False)
#     disability = models.BooleanField(default=False)
#     illness    = models.BooleanField(default=False)
#     accident   = models.BooleanField(default=False)
#     medical    = models.BooleanField(default=False)

class Invoice(models.Model):
    class Meta:
        db_table            = 'Invoice'
        verbose_name_plural = 'Invoice'

    company          = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE)
    invoice_no       = models.CharField(max_length=50, null=False, blank=False)
    senangpay_refno  = models.CharField(max_length=50, null=True, blank=True)
    total_amount     = models.CharField(max_length=50, null=False, blank=False)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_datetime = models.DateTimeField(null=True, blank=True)
    click_datetime   = models.DateTimeField(null=True, blank=True)
    status           = models.CharField(max_length=50, null=False, blank=False)
    description      = models.CharField(max_length=500, null=True, blank=True)
    hash_value       = models.CharField(max_length=255, null=True, blank=True)
    deartime_orderid = models.IntegerField(blank=True, null=True)
    receipt_no       = models.CharField(max_length=50, null=True, blank=True)
    payment_reminder = models.IntegerField(blank=True, null=True)
    remarks          = models.CharField(max_length=100, null=True, blank=True)
    payment_date     = models.DateTimeField(null=True, blank=True)

class Order(models.Model):
    class Meta:
        db_table            = 'Order'
        verbose_name_plural = 'Order'
    
    invoice          = models.ForeignKey(Invoice, on_delete=models.CASCADE)
    member           = models.ForeignKey(Member, on_delete=models.CASCADE)
    order_no         = models.CharField(max_length=50, null=False, blank=False)
    amount           = models.CharField(max_length=50, null=False, blank=False)
    true_amount      = models.CharField(max_length=50, null=True, blank=True)
    created_by       = models.ForeignKey(CorporateUser, on_delete=models.CASCADE, blank=False, null=False, related_name="%(class)s_created_by_user")
    created_datetime = models.DateTimeField(auto_now_add=True)
    
class MemberCoveragePremium(models.Model):
    class Meta:
        db_table            = 'MemberCoveragePremium'
        verbose_name_plural = 'Member Coverage Premium'
    
    member           = models.ForeignKey(Member, on_delete=models.CASCADE)
    product          = models.ForeignKey(Product, on_delete=models.CASCADE)
    payment_monthly  = models.FloatField()
    payment_annually = models.FloatField()
    created_datetime = models.DateTimeField(auto_now_add=True)

class MemberProductMapping(models.Model):
    class Meta:
        db_table            = 'MemberProductMapping'
        verbose_name_plural = 'Member Product Mapping'

    member              = models.ForeignKey(Member, on_delete=models.CASCADE)
    product             = models.ForeignKey(Product, on_delete=models.CASCADE)
    deartime_coverageid = models.IntegerField(null=True, blank=True)
    coverage_amount     = models.DecimalField(default=0.00, blank=False, null=False, decimal_places=2, max_digits=50)
    created_datetime    = models.DateTimeField(auto_now_add=True)
    updated_datetime    = models.DateTimeField(null=True, blank=True)
    is_terminated       = models.BooleanField(default=False)
    is_renewal          = models.BooleanField(default=False)
    
class UploadMemberFilenames(models.Model):
    class Meta:
        db_table            = 'UploadMemberFilenames'
        verbose_name_plural = 'Upload Member Filenames'

    corporate        = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE)
    original         = models.CharField(max_length=200, null=False, blank=False)
    renamed          = models.CharField(max_length=200, null=False, blank=False)
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_datetime = models.DateTimeField(null=True, blank=True)

class LoginAttemptControl(models.Model):
    class Meta:
        db_table            = 'LoginAttemptControl'
        verbose_name_plural = 'Login Attempt Control'
    
    user             = models.ForeignKey(CorporateUser, on_delete=models.CASCADE)
    attempts         = models.SmallIntegerField(default=1, blank=True, null=True)
    attempt_datetime = models.DateTimeField(auto_now_add=True)

class FAQ(models.Model):
    class Meta:
        db_table            = 'FAQ'
        verbose_name_plural = 'Frequently Ask Questions'
    
    product      = models.ForeignKey(Product, on_delete=models.CASCADE)
    title        = models.CharField(max_length=200,null=False,blank=False)
    description  = models.TextField(null=False,blank=False)
    faq_type     = models.CharField(max_length=100,null=True,blank=True)    

class CurrentDate(models.Model):
    class Meta:
        db_table            = 'CurentDate'
        verbose_name_plural = 'Curent Date'
    
    corporate    = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE)
    current_datetime = models.DateTimeField(null=True, blank=True)
    created_datetime = models.DateTimeField(auto_now_add=True)
    updated_datetime = models.DateTimeField(null=True, blank=True)
    
class PremiumAdjustment(models.Model):
    class Meta:
        db_table            = 'PremiumAdjustment'
        verbose_name_plural = 'Premium Adjustment'
    
    member              = models.ForeignKey(Member, on_delete=models.CASCADE)
    ad_premium          = models.DecimalField(default=0.00, blank=False, null=False, decimal_places=2, max_digits=50)
    remarks             = models.CharField(max_length=250, null=True, blank=True)
    paid                = models.BooleanField(default=False)
    generated_invoice   = models.BooleanField(default=False)
    void                = models.BooleanField(default=False)
    created_datetime    = models.DateTimeField(auto_now_add=True)    
class  PaymentModeHistory(models.Model):
    class Meta:
            db_table            = 'PaymentModeHistory'
            verbose_name_plural = 'PaymentModeHistory'

    corporate            = models.ForeignKey(CorporateProfile, on_delete=models.CASCADE, blank=False, null=False)
    created_datetime     = models.DateTimeField(auto_now_add=True)
    updated_datetime     = models.DateTimeField(null=True, blank=True)
    old_payment_due_date = models.CharField(max_length=25, blank=False, null=False)
    old_payment_mode     = models.CharField(max_length=25, blank=False, null=False)
    new_payment_due_date = models.CharField(max_length=25, blank=False, null=False)
    new_payment_mode     = models.CharField(max_length=25, blank=False, null=False)
    is_updated           = models.BooleanField(default=False)
    is_void              = models.BooleanField(default=False)
