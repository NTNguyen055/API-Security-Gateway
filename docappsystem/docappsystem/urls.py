from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

from . import views, adminviews, docviews, userviews

import logging

logger = logging.getLogger(__name__)


# =========================
# Health Check
# =========================
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
    path('login/', views.LOGIN, name='login'),
    path('login/submit/', views.doLogin, name='do_login'),
    path('logout/', views.doLogout, name='logout'),

    # -------------------------
    # Health
    # -------------------------
    path('health/', health_check),

    # =========================
    # ADMIN PANEL
    # =========================
    path('admin/dashboard/', adminviews.ADMINHOME, name='admin_home'),

    path('admin/specializations/', adminviews.SPECIALIZATION, name='add_specialization'),
    path('admin/specializations/manage/', adminviews.MANAGESPECIALIZATION, name='manage_specialization'),
    path('admin/specializations/<str:id>/delete/', adminviews.DELETE_SPECIALIZATION, name='delete_specialization'),
    path('admin/specializations/<str:id>/update/', adminviews.UPDATE_SPECIALIZATION, name='update_specialization'),
    path('admin/specializations/update/submit/', adminviews.UPDATE_SPECIALIZATION_DETAILS, name='update_specialization_details'),

    path('admin/doctors/', adminviews.DoctorList, name='doctor_list'),
    path('admin/doctors/<str:id>/', adminviews.ViewDoctorDetails, name='doctor_detail'),
    path('admin/doctors/<str:id>/appointments/', adminviews.ViewDoctorAppointmentList, name='doctor_appointments'),
    path('admin/patients/<str:id>/', adminviews.ViewPatientDetails, name='patient_detail'),

    path('admin/search/doctor/', adminviews.Search_Doctor, name='search_doctor'),
    path('admin/reports/doctor/date-range/', adminviews.Doctor_Between_Date_Report, name='doctor_date_report'),

    # Website config
    path('admin/website/', adminviews.WEBSITE_UPDATE, name='website_update'),
    path('admin/website/update/', adminviews.UPDATE_WEBSITE_DETAILS, name='update_website'),

    # =========================
    # DOCTOR PANEL
    # =========================
    path('doctor/signup/', docviews.DOCSIGNUP, name='doctor_signup'),
    path('doctor/dashboard/', docviews.DOCTORHOME, name='doctor_home'),

    path('doctor/appointments/', docviews.View_Appointment, name='view_appointments'),
    path('doctor/appointments/<str:id>/', docviews.Patient_Appointment_Details, name='appointment_detail'),

    path('doctor/appointments/remark/update/', docviews.Patient_Appointment_Details_Remark,
         name='appointment_remark_update'),

    path('doctor/appointments/status/approved/', docviews.Patient_Approved_Appointment,
         name='approved_appointments'),

    path('doctor/appointments/status/cancelled/', docviews.Patient_Cancelled_Appointment,
         name='cancelled_appointments'),

    path('doctor/appointments/status/new/', docviews.Patient_New_Appointment,
         name='new_appointments'),

    path('doctor/appointments/list/approved/', docviews.Patient_List_Approved_Appointment,
         name='approved_appointment_list'),

    path('doctor/<str:id>/appointments/', docviews.DoctorAppointmentList, name='doctor_appointment_list'),

    path('doctor/prescriptions/', docviews.Patient_Appointment_Prescription, name='prescription'),
    path('doctor/appointments/completed/', docviews.Patient_Appointment_Completed, name='completed_appointments'),

    path('doctor/search/appointments/', docviews.Search_Appointments, name='search_appointments'),
    path('doctor/reports/date-range/', docviews.Between_Date_Report, name='doctor_date_report'),

    # =========================
    # USER PANEL
    # =========================
    path('', userviews.Index, name='index'),

    path('user/base/', userviews.USERBASE, name='user_base'),
    path('user/appointment/create/', userviews.create_appointment, name='create_appointment'),
    path('user/appointment/search/', userviews.User_Search_Appointments, name='user_search_appointment'),

    path('user/appointment/<str:id>/', userviews.View_Appointment_Details, name='user_appointment_detail'),

    # =========================
    # PROFILE
    # =========================
    path('profile/', views.PROFILE, name='profile'),
    path('profile/update/', views.PROFILE_UPDATE, name='profile_update'),
    path('profile/password/', views.CHANGE_PASSWORD, name='change_password'),

]

# =========================
# Media (Dev only)
# =========================
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)