from django.contrib import admin
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Import các views
from . import views, adminviews, docviews, userviews

# ============================================================
# HEALTH CHECK (OPTIMIZED FOR GATEWAY + DOCKER + JENKINS)
# ============================================================
@csrf_exempt
def health_check(request):
    return JsonResponse({"status": "ok"}, status=200)

urlpatterns = [

    # =========================================================
    # PUBLIC (NO JWT REQUIRED)
    # =========================================================
    path('login/', views.LOGIN, name='login'),
    path('doLogin/', views.doLogin, name='doLogin'),
    
    # Đảm bảo match cả /health và /health/ để tránh 301 Redirect Loop
    path('health/', health_check, name='health'),
    path('health', health_check),

    # =========================================================
    # BASE / USER
    # =========================================================
    path('', userviews.Index, name='index'),
    path('base/', views.BASE, name='base'),
    path('userbase/', userviews.USERBASE, name='userbase'),

    path('userappointment/', userviews.create_appointment, name='appointment'),
    path('User_SearchAppointment/', userviews.User_Search_Appointments, name='user_search_appointment'),
    path('ViewAppointmentDetails/<str:id>/', userviews.View_Appointment_Details, name='viewappointmentdetails'),

    # =========================================================
    # PROFILE
    # =========================================================
    path('profile/', views.PROFILE, name='profile'),
    path('profile/update/', views.PROFILE_UPDATE, name='profile_update'),
    path('password/', views.CHANGE_PASSWORD, name='change_password'),

    # =========================================================
    # ADMIN PANEL
    # =========================================================
    path('admin/', admin.site.urls),

    path('admin/home/', adminviews.ADMINHOME, name='admin_home'),
    path('admin/specialization/', adminviews.SPECIALIZATION, name='add_specilizations'),
    path('admin/manage-specialization/', adminviews.MANAGESPECIALIZATION, name='manage_specilizations'),
    path('admin/delete-specialization/<str:id>/', adminviews.DELETE_SPECIALIZATION, name='delete_specilizations'),
    path('admin/update-specialization/<str:id>/', adminviews.UPDATE_SPECIALIZATION, name='update_specilizations'),
    path('admin/update-specialization-details/', adminviews.UPDATE_SPECIALIZATION_DETAILS, name='update_specilizations_details'),

    path('admin/doctor-list/', adminviews.DoctorList, name='viewdoctorlist'),
    path('admin/view-doctor-details/<str:id>/', adminviews.ViewDoctorDetails, name='viewdoctordetails'),
    path('admin/view-doctor-appointments/<str:id>/', adminviews.ViewDoctorAppointmentList, name='viewdoctorappointmentlist'),
    path('admin/view-patient-details/<str:id>/', adminviews.ViewPatientDetails, name='viewpatientdetails'),

    path('admin/search-doctor/', adminviews.Search_Doctor, name='search_doctor'),
    path('admin/doctor-report/', adminviews.Doctor_Between_Date_Report, name='doctor_between_date_report'),

    path('admin/website/update/', adminviews.WEBSITE_UPDATE, name='website_update'),
    path('admin/website/update-details/', adminviews.UPDATE_WEBSITE_DETAILS, name='update_website_details'),

    # =========================================================
    # DOCTOR PANEL
    # =========================================================
    path('doctor/signup/', docviews.DOCSIGNUP, name='docsignup'),
    path('doctor/home/', docviews.DOCTORHOME, name='doctor_home'),

    path('doctor/view-appointment/', docviews.View_Appointment, name='view_appointment'),
    path('doctor/appointment-details/<str:id>/', docviews.Patient_Appointment_Details, name='patientappointmentdetails'),
    path('doctor/appointment-remark/update/', docviews.Patient_Appointment_Details_Remark, name='patient_appointment_details_remark'),

    path('doctor/appointments/approved/', docviews.Patient_Approved_Appointment, name='patientapprovedappointment'),
    path('doctor/appointments/cancelled/', docviews.Patient_Cancelled_Appointment, name='patientcancelledappointment'),
    path('doctor/appointments/new/', docviews.Patient_New_Appointment, name='patientnewappointment'),
    path('doctor/appointments/list-approved/', docviews.Patient_List_Approved_Appointment, name='patientlistappointment'),

    path('doctor/appointment-list/<str:id>/', docviews.DoctorAppointmentList, name='doctorappointmentlist'),
    path('doctor/prescription/', docviews.Patient_Appointment_Prescription, name='patientappointmentprescription'),
    path('doctor/completed/', docviews.Patient_Appointment_Completed, name='patientappointmentcompleted'),

    path('doctor/search-appointment/', docviews.Search_Appointments, name='search_appointment'),
    path('doctor/report/', docviews.Between_Date_Report, name='between_date_report'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)