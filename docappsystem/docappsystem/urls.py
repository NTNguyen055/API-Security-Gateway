from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.db import connection, transaction # Thêm transaction

# Import thư viện auth mặc định của Django
from django.contrib.auth import views as auth_views

# Import views
from . import views, adminviews, docviews, userviews

# ============================================================
# HEALTH CHECK
# ============================================================
@csrf_exempt # Chỉ dùng cho GET. Nếu chuyển sang POST, cần cân nhắc gỡ bỏ để đảm bảo bảo mật.
@require_http_methods(["GET"])
def health_check(request):
    """
    Lightweight health check cho Docker, gateway, và Cloud Watch.
    Kiểm tra DB connection (trong transaction) và Redis cache.
    """
    checks = {}
    healthy = True

    # Kiểm tra DB - Sử dụng transaction.atomic để cô lập check
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = f"error: {type(e).__name__}"
        healthy = False

    # Kiểm tra Redis cache
    try:
        from django.core.cache import cache
        cache.set("_health_ping", "1", timeout=5)
        if cache.get("_health_ping") == "1":
            checks["cache"] = "ok"
        else:
            checks["cache"] = "unexpected_value"
    except Exception as e:
        # Cache fail không làm sập hệ thống nhưng cần log lại
        checks["cache"] = f"error: {type(e).__name__}"
        # healthy = False  <-- Tùy chọn: Giữ True nếu bạn coi Cache là non-critical

    status_code = 200 if healthy else 503
    return JsonResponse({"status": "healthy" if healthy else "unhealthy", "checks": checks}, status=status_code)


# ============================================================
# URL CONFIGURATION
# ============================================================
urlpatterns = [
    # Cổng Admin mặc định
    path('admin/', admin.site.urls),
    
    # Health check
    path("health/", health_check, name="health_check"),

    # AUTHENTICATION
    path("", views.Index, name="index"),
    path("login/", views.LOGIN, name="login"),
    path("doLogin/", views.doLogin, name="doLogin"),
    
    # Logout: Sử dụng built-in của Django
    # Lưu ý: /logout/ đã được thêm vào PUBLIC_PATHS trong middleware.py 
    # để tránh redirect loop sau khi session bị hủy.
    path("logout/", auth_views.LogoutView.as_view(next_page='login'), name="logout"),

    # ── CUSTOM ADMIN ROUTES ──────────────────────────────────────
    # Lưu ý bảo mật: Các route này bắt đầu bằng /admin/ nên 
    # cần được Nginx gateway áp dụng các layer bảo mật tương đương admin/
    path("admin/home/", adminviews.AdminHome, name="admin_home"),
    path("admin/doctor-list/", adminviews.DoctorList, name="doctorlist"),
    path("admin/doctor-view/<int:id>/", adminviews.DoctorView, name="doctorview"),
    path("admin/doctor-delete/<int:id>/", adminviews.DoctorDelete, name="doctordelete"),
    path("admin/specialization-list/", adminviews.SpecializationList, name="specializationlist"),
    path("admin/specialization-delete/<int:id>/", adminviews.SpecializationDelete, name="specializationdelete"),
    path("admin/patient-list/", adminviews.PatientList, name="patientlist"),
    path("admin/patient-view/<int:id>/", adminviews.PatientView, name="patientview"),
    path("admin/appointment-list/", adminviews.AppointmentList, name="appointmentlist"),
    path("admin/appointment-view/<int:id>/", adminviews.AppointmentView, name="appointmentview"),
    path("admin/report/", adminviews.AdminReport, name="adminreport"),

    # ── USER ROUTES ──────────────────────────────────────────────
    path("patient/signup/", userviews.PatientSignup, name="patientsignup"),
    path("patient/home/", userviews.PatientHome, name="patient_home"),
    path("patient/book-appointment/", userviews.Book_Appointment, name="book_appointment"),
    path("patient/appointment-history/", userviews.Appointment_History, name="appointment_history"),
    path("patient/appointment-details/<int:id>/", userviews.Appointment_Details, name="appointment_details"),

    # ── DOCTOR ROUTES ────────────────────────────────────────────
    path("doctor/signup/", docviews.DoctorSignup, name="doctorsignup"),
    path("doctor/home/", docviews.DoctorHome, name="doctor_home"),
    path("doctor/appointment-details/<int:id>/", 
         docviews.Patient_Appointment_Details_Remark, 
         name="patient_appointment_details_remark"),

    path("doctor/appointments/approved/", 
         docviews.Patient_Approved_Appointment, name="patientapprovedappointment"),
    path("doctor/appointments/cancelled/", 
         docviews.Patient_Cancelled_Appointment, name="patientcancelledappointment"),
    path("doctor/appointments/new/", 
         docviews.Patient_New_Appointment, name="patientnewappointment"),
    path("doctor/appointments/list-approved/", 
         docviews.Patient_List_Approved_Appointment, name="patientlistappointment"),

    path("doctor/appointment-list/<int:id>/", 
         docviews.DoctorAppointmentList, name="doctorappointmentlist"),
    path("doctor/prescription/", 
         docviews.Patient_Appointment_Prescription, 
         name="patientappointmentprescription"),
    path("doctor/completed/", 
         docviews.Patient_Appointment_Completed, name="patientappointmentcompleted"),

    path("doctor/search-appointment/", 
         docviews.Search_Appointments, name="search_appointment"),
    path("doctor/report/", 
         docviews.Between_Date_Report, name="between_date_report"),
]

# ── STATIC & MEDIA ───────────────────────────────────────────
if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)