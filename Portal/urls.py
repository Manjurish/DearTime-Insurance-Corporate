from django.urls import path
from django.contrib import admin
from .views import *

admin.site.site_header = 'Backoffice Sites'
admin.site.index_title = 'DearTime'
admin.site.site_title  = 'Backoffice Sites'
admin.site.site_url    = ''

handler404 = 'Portal.views.handler404'
handler500 = 'Portal.views.handler500'
handler403 = 'Portal.views.handler403'
handler400 = 'Portal.views.handler400'
handler401 = 'Portal.views.handler401'
handler503 = 'Portal.views.handler503'

urlpatterns = [
    path('', LoginView, name='login_page'),
    path('dashboard', DashboardView, name='dashboard_page'),
    path('download/templates/<str:template_name>', DownloadTemplates, name='download_templates'),
    path('download-failed-uploads/<str:fileName>/<str:companySalt>', DownloadFailedUploads, name='download-failed-uploads'),
    path('download-previous-uploads/<str:fileName>/<str:companySalt>', DownloadPreviousUploads, name='download-previous-uploads'),
    path('terminate-member', DeleteMember, name='terminate_member'),
    path('reoffer-member', ReofferMember, name='reoffer-member'),
    path('logout', LogOutView, name='logout'),
    path('reset-password', ResetPasswordView, name='reset_password_page'),
    path('reset-password-email/<uidb64>/<token>', ResetPasswordEmailView, name='reset-password-email'),
    path('set-new-password', SetNewPassword, name='set-new-password'),
    path('sign-up', SignUpView, name='sign_up_page'),
    path('company-registration-login/<str:companySalt>', CompanyRegistrationViewLogin, name='company_registration_login'),
    path('company-registration/<uidb64>/<token>', CompanyRegistrationView, name='company_registration_page'),
    path('submitted-registration', SubmittedCompanyRegistrationView, name='submitted_company_registration_page'),
    path('company-approval', CompanyApprovalListView, name='company_approval_page'),
    path('edit-company-account/<str:companySalt>', EditCompanyAccountView, name='edit_company_account_page'),
    path('resend-link/<uidb64>/<token>/<int:flag>', ResendLinkView, name='resend-link'),
    path('add-member', AddMember, name='add-member'),
    path('member-list', MemberListView, name='member_list_page'),
    path('upload-corporate-form/<str:companySalt>/<str:form_type>', UploadCorporateForm, name='upload-corporate-form'),
    path('remove-corporate-form/<str:companySalt>/<str:form_type>', RemoveCorporateForm, name='remove-corporate-form'),
    path('upload-member-spreadsheet', UploadMemberSpreadsheet, name='upload-member-spreadsheet'),
    path('company-approval-member/<str:companySalt>', CompanyApprovalMemberListView, name='company_approval_member_page'),
    path('company-modify-PDD', CompanyModifyPDDListView, name='company_modify_PDD'),
    path('ammend-PDD', CompanyAmmendPDD, name='company_ammend_PDD'),
    path('ammend-CD', CompanyAmmendCD, name='company_ammend_CD'),
    path('premium-adjustment', premiumAdjustment, name='premium_adjustment'),
    path('reset-CD', CompanyResetCD, name='company_reset_CD'),
    path('package-list/<str:companySalt>', PackageListView, name='package-list-page'),
    path('edit-package/<str:companySalt>', EditPackage, name='edit-package'),
    path('edit-member', EditMember, name='edit_member'),
    path('generate-invoice', GenerateInvoicePDF, name='generate_invoice_page'),
    path('failed-upload-list/<str:companySalt>', FailedUploadListView, name='failed-upload-list-page'),
    path('view-company-account/<str:companySalt>', ViewCompanyAccountView, name='view_company_account_page'),
    path('invoice-payment', InvoicePayment, name='invoice_payment'),
    path('view-invoice/<str:invoiceSalt>/<str:type>', ViewInvoiceView, name='view-invoice'),
    path('invoice-list', InvoiceListView, name='invoice_list_page'),
    path('cancel-invoice', CancelInvoiceView, name='cancel-invoice'),
    path('download/form/<str:form_name>', DownloadForm, name='download_form'),
    path('change-password', ChangePassword, name='change-password'),
    path('referral',RefferalView,name='referral'),
    path('referral-without-bank',RefferalViewWithoutBank,name='referral-without-bank'),
    path('general',GeneralView,name='general'),
    path('upload-history/<str:companySalt>',UploadHistoryView,name='upload-history-page'),
    path('view-uploaded-file/<str:fileName>/<str:companySalt>',ViewUploadedFile,name='view-uploaded-file-page'),
    path('user-enquiry', DeleteUser, name='user-enquiry'),
    path('clear-user', ClearUsers, name='clear-user'),
    path('member-renewal', memberRenewal, name='member-renewal'),
    path('export-corporate-list', ExportCorporatelist, name='export_corporate_list'),
    path('export-rejected-corporate-list', ExportRejectedCorporatelist, name='export_rejected_corporate_list'),
    path('export-member-list', ExportMemberList, name='export-member-list'),
]
