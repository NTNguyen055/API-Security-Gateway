from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse

from . import views, adminviews, docviews, userviews

# =========================
# HEALTH CHECK (PRODUCTION READY)
# =========================
def health_check(request):
    return JsonResponse({"status": "ok"}, status=200)


# =========================
# URL PATTERNS
# =========================
urlpatterns = [

    # =========================
    # CORE
    # =========================
    path('health/', health_check, name='health'),

    # =========================
    # ADMIN
    # =========================
    path('admin/', admin.site.urls),

    path('admin/home/', adminviews.ADMINHOME, name='admin_home'),
    path('admin/specialization/', adminviews.SPECIALIZATION),
    path('admin/specialization/manage/', adminviews.MANAGESPECIALIZATION),
    path('admin/specialization/delete/<str:id>/', adminviews.DELETE_SPECIALIZATION),
    path('admin/specialization/update/<str:id>/', adminviews.UPDATE_SPECIALIZATION),
    path('admin/specialization/update/details/', adminviews.UPDATE_SPECIALIZATION_DETAILS),

    path('admin/doctor/', adminviews.DoctorList),
    path('admin/doctor/<str:id>/', adminviews.ViewDoctorDetails),
    path('admin/doctor/<str:id>/appointments/', adminviews.ViewDoctorAppointmentList),
    path('admin/patient/<str:id>/', adminviews.ViewPatientDetails),

    path('admin/search/doctor/', adminviews.Search_Doctor),
    path('admin/report/doctor/', adminviews.Doctor_Between_Date_Report),

    path('admin/website/update/', adminviews.WEBSITE_UPDATE),
    path('admin/website/update/details/', adminviews.UPDATE_WEBSITE_DETAILS),

    # =========================
    # AUTH
    # =========================
    path('auth/login/', views.LOGIN),
    path('auth/do-login/', views.doLogin),
    path('auth/logout/', views.doLogout),

    # =========================
    # DOCTOR
    # =========================
    path('doctor/signup/', docviews.DOCSIGNUP),
    path('doctor/home/', docviews.DOCTORHOME),

    path('doctor/appointments/', docviews.View_Appointment),
    path('doctor/appointments/<str:id>/', docviews.Patient_Appointment_Details),
    path('doctor/appointments/update/', docviews.Patient_Appointment_Details_Remark),

    path('doctor/appointments/approved/', docviews.Patient_Approved_Appointment),
    path('doctor/appointments/cancelled/', docviews.Patient_Cancelled_Appointment),
    path('doctor/appointments/new/', docviews.Patient_New_Appointment),
    path('doctor/appointments/list/', docviews.Patient_List_Approved_Appointment),

    path('doctor/appointments/<str:id>/list/', docviews.DoctorAppointmentList),

    path('doctor/prescription/', docviews.Patient_Appointment_Prescription),
    path('doctor/completed/', docviews.Patient_Appointment_Completed),

    path('doctor/search/', docviews.Search_Appointments),
    path('doctor/report/', docviews.Between_Date_Report),

    # =========================
    # USER
    # =========================
    path('', userviews.Index),

    path('user/base/', userviews.USERBASE),
    path('user/appointment/', userviews.create_appointment),
    path('user/search/', userviews.User_Search_Appointments),
    path('user/appointment/<str:id>/', userviews.View_Appointment_Details),

    # =========================
    # PROFILE
    # =========================
    path('user/profile/', views.PROFILE),
    path('user/profile/update/', views.PROFILE_UPDATE),
    path('user/password/', views.CHANGE_PASSWORD),

]

# =========================
# MEDIA (DEV ONLY)
# =========================
if settings.DEBUG and not getattr(settings, "USE_S3", False):
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)