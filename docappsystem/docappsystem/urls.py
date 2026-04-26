from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.http import HttpResponse

from . import views, adminviews, docviews, userviews

import logging

logger = logging.getLogger(__name__)


# =========================
# Health Check
# =========================
# FIX: trả về body "OK" để dễ debug hơn khi inspect log.
# csrf_exempt bỏ — GET request không cần exempt CSRF.
def health_check(request):
    return HttpResponse("OK", status=200)


# =========================
# URL Patterns
# =========================
urlpatterns = [

    # -------------------------
    # Admin
    # -------------------------
    path('admin/', admin.site.urls),

    path('base/', views.BASE, name='base'),

    # -------------------------
    # Authentication
    # -------------------------
    path('login', views.LOGIN, name='login'),
    path('doLogin', views.doLogin, name='doLogin'),
    path('doLogout', views.doLogout, name='logout'),

    # -------------------------
    # Health
    # -------------------------
    path('health/', health_check),

    # =========================
    # ADMIN PANEL
    # =========================
    path('Admin/AdminHome', adminviews.ADMINHOME, name='admin_home'),

    path('Admin/Specialization', adminviews.SPECIALIZATION, name='add_specilizations'),
    path('Admin/ManageSpecialization', adminviews.MANAGESPECIALIZATION, name='manage_specilizations'),
    path('Admin/DeleteSpecialization/<str:id>', adminviews.DELETE_SPECIALIZATION, name='delete_specilizations'),
    path('UpdateSpecialization/<str:id>', adminviews.UPDATE_SPECIALIZATION, name='update_specilizations'),
    path('UPDATE_Specialization_DETAILS', adminviews.UPDATE_SPECIALIZATION_DETAILS, name='update_specilizations_details'),

    path('Admin/DoctorList', adminviews.DoctorList, name='viewdoctorlist'),
    path('Admin/ViewDoctorDetails/<str:id>', adminviews.ViewDoctorDetails, name='viewdoctordetails'),
    path('Admin/ViewDoctorAppointmentList/<str:id>', adminviews.ViewDoctorAppointmentList, name='viewdoctorappointmentlist'),
    path('Admin/ViewPatientDetails/<str:id>', adminviews.ViewPatientDetails, name='viewpatientdetails'),

    path('SearchDoctor', adminviews.Search_Doctor, name='search_doctor'),
    path('DoctorBetweenDateReport', adminviews.Doctor_Between_Date_Report, name='doctor_between_date_report'),

    # Website config
    path('Website/update', adminviews.WEBSITE_UPDATE, name='website_update'),
    path('UPDATE_WEBSITE_DETAILS', adminviews.UPDATE_WEBSITE_DETAILS, name='update_website_details'),

    # =========================
    # DOCTOR PANEL
    # =========================
    path('docsignup/', docviews.DOCSIGNUP, name='docsignup'),
    path('Doctor/DocHome', docviews.DOCTORHOME, name='doctor_home'),

    path('Doctor/ViewAppointment', docviews.View_Appointment, name='view_appointment'),
    path('DoctorPatientAppointmentDetails/<str:id>', docviews.Patient_Appointment_Details, name='patientappointmentdetails'),
    path('AppointmentDetailsRemark/Update', docviews.Patient_Appointment_Details_Remark, name='patient_appointment_details_remark'),

    path('DoctorPatientApprovedAppointment', docviews.Patient_Approved_Appointment, name='patientapprovedappointment'),
    path('DoctorPatientCancelledAppointment', docviews.Patient_Cancelled_Appointment, name='patientcancelledappointment'),
    path('DoctorPatientNewAppointment', docviews.Patient_New_Appointment, name='patientnewappointment'),
    path('DoctorPatientListApprovedAppointment', docviews.Patient_List_Approved_Appointment, name='patientlistappointment'),
    path('DoctorAppointmentList/<str:id>', docviews.DoctorAppointmentList, name='doctorappointmentlist'),

    path('PatientAppointmentPrescription', docviews.Patient_Appointment_Prescription, name='patientappointmentprescription'),
    path('PatientAppointmentCompleted', docviews.Patient_Appointment_Completed, name='patientappointmentcompleted'),

    path('SearchAppointment', docviews.Search_Appointments, name='search_appointment'),
    path('BetweenDateReport', docviews.Between_Date_Report, name='between_date_report'),

    # =========================
    # USER PANEL
    # =========================
    path('', userviews.Index, name='index'),

    path('userbase/', userviews.USERBASE, name='userbase'),
    path('userappointment/', userviews.create_appointment, name='appointment'),
    path('User_SearchAppointment', userviews.User_Search_Appointments, name='user_search_appointment'),
    path('ViewAppointmentDetails/<str:id>/', userviews.View_Appointment_Details, name='viewappointmentdetails'),

    # =========================
    # PROFILE
    # =========================
    path('Profile', views.PROFILE, name='profile'),
    path('Profile/update', views.PROFILE_UPDATE, name='profile_update'),
    path('Password', views.CHANGE_PASSWORD, name='change_password'),

]

# =========================
# Media (Dev only, non-S3)
# =========================
# FIX: guard rõ ràng — chỉ serve media local khi DEBUG và không dùng S3.
# static() đã trả về [] khi DEBUG=False, nhưng guard này tự document
# rõ ý định hơn và tránh nhầm lẫn khi đọc code.
if settings.DEBUG and not getattr(settings, "USE_S3", False):
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
