# Import các hàm render giao diện, chuyển hướng và trả về HTTP response
from multiprocessing import context
from django.shortcuts import render, redirect, HttpResponse

# Decorator yêu cầu người dùng phải đăng nhập mới được truy cập view
from django.contrib.auth.decorators import login_required

# Import các model từ app dasapp
from dasapp.models import DoctorReg, Specialization, CustomUser, Appointment

# Import hệ thống message để hiển thị thông báo (success, warning, error)
from django.contrib import messages

# Import thư viện phân trang
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# Import datetime để xử lý ngày tháng
from datetime import datetime

# FIX: Import thêm Q object để xử lý các câu lệnh truy vấn phức tạp (OR/AND) an toàn
from django.db.models import Q 


# View đăng ký bác sĩ
def DOCSIGNUP(request):
    specialization = Specialization.objects.all()

    if request.method == "POST":
        pic = request.FILES.get('pic')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        mobno = request.POST.get('mobno')
        specialization_id = request.POST.get('specialization_id')
        password = request.POST.get('password')

        if CustomUser.objects.filter(email=email).exists():
            messages.warning(request, 'Email already exist')
            return redirect('docsignup')

        if CustomUser.objects.filter(username=username).exists():
            messages.warning(request, 'Username already exist')
            return redirect('docsignup')

        else:
            user = CustomUser(
               first_name=first_name,
               last_name=last_name,
               username=username,
               email=email,
               user_type=2,
               profile_pic=pic,
            )
            user.set_password(password)
            user.save()

            spid = Specialization.objects.get(id=specialization_id)
            doctor = DoctorReg(
                admin=user,
                mobilenumber=mobno,
                specialization_id=spid,
            )
            doctor.save()
            messages.success(request, 'Signup Successfully')
            return redirect('docsignup')

    context = {
        'specialization': specialization
    }
    return render(request, 'doc/docreg.html', context)


# Trang dashboard chính của bác sĩ
@login_required(login_url='/')
def DOCTORHOME(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    allaptcount = Appointment.objects.filter(doctor_id=doctor_reg).count()
    newaptcount = Appointment.objects.filter(status='0', doctor_id=doctor_reg).count()
    appaptcount = Appointment.objects.filter(status='Approved', doctor_id=doctor_reg).count()
    canaptcount = Appointment.objects.filter(status='Cancelled', doctor_id=doctor_reg).count()
    comaptcount = Appointment.objects.filter(status='Completed', doctor_id=doctor_reg).count()

    context = {
        'newaptcount': newaptcount,
        'allaptcount': allaptcount,
        'appaptcount': appaptcount,
        'canaptcount': canaptcount,
        'comaptcount': comaptcount
    }
    return render(request, 'doc/dochome.html', context)


# Xem danh sách lịch hẹn của bác sĩ
def View_Appointment(request):
    try:
        doctor_admin = request.user
        doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

        # FIX 1: Thêm .order_by('-id') để khắc phục lỗi UnorderedObjectListWarning
        # Sắp xếp lịch hẹn mới nhất lên đầu, giúp Paginator cắt trang chính xác
        view_appointment = Appointment.objects.filter(doctor_id=doctor_reg).order_by('-id')

        paginator = Paginator(view_appointment, 5)
        page = request.GET.get('page')

        try:
            view_appointment = paginator.page(page)
        except PageNotAnInteger:
            view_appointment = paginator.page(1)
        except EmptyPage:
            view_appointment = paginator.page(paginator.num_pages)

        context = {'view_appointment': view_appointment}

    except Exception as e:
        context = {'error_message': str(e)}

    return render(request, 'doc/view_appointment.html', context)


# Xem chi tiết lịch hẹn của bệnh nhân
def Patient_Appointment_Details(request, id):
    patientdetails = Appointment.objects.filter(id=id)
    context = {'patientdetails': patientdetails}
    return render(request, 'doc/patient_appointment_details.html', context)


# Cập nhật trạng thái lịch hẹn và ghi chú
def Patient_Appointment_Details_Remark(request):
    if request.method == 'POST':
        patient_id = request.POST.get('pat_id')
        remark = request.POST['remark']
        status = request.POST['status']

        patientaptdet = Appointment.objects.get(id=patient_id)
        patientaptdet.remark = remark
        patientaptdet.status = status
        patientaptdet.save()

        messages.success(request, "Status Update successfully")
        return redirect('view_appointment')

    return render(request, 'doc/view_appointment.html', {})


# Xem danh sách lịch hẹn đã duyệt
def Patient_Approved_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Approved', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_app_appointment.html', context)


# Xem danh sách lịch hẹn đã hủy
def Patient_Cancelled_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Cancelled', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_app_appointment.html', context)


# Xem danh sách lịch hẹn mới
def Patient_New_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='0', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_app_appointment.html', context)


# Xem danh sách lịch hẹn đã duyệt (dạng list khác)
def Patient_List_Approved_Appointment(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Approved', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_list_app_appointment.html', context)


# Xem chi tiết lịch hẹn
def DoctorAppointmentList(request, id):
    patientdetails = Appointment.objects.filter(id=id)
    context = {'patientdetails': patientdetails}
    return render(request, 'doc/doctor_appointment_list_details.html', context)


# Cập nhật đơn thuốc và xét nghiệm
def Patient_Appointment_Prescription(request):
    if request.method == 'POST':
        patient_id = request.POST.get('pat_id')
        prescription = request.POST['prescription']
        recommendedtest = request.POST['recommendedtest']
        status = request.POST['status']

        patientaptdet = Appointment.objects.get(id=patient_id)
        patientaptdet.prescription = prescription
        patientaptdet.recommendedtest = recommendedtest
        patientaptdet.status = status
        patientaptdet.save()

        messages.success(request, "Status Update successfully")
        return redirect('view_appointment')

    return render(request, 'doc/patient_list_app_appointment.html', {})


# Xem lịch hẹn đã hoàn thành
def Patient_Appointment_Completed(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)
    # FIX: Thêm order_by('-id')
    patientdetails1 = Appointment.objects.filter(status='Completed', doctor_id=doctor_reg).order_by('-id')
    context = {'patientdetails1': patientdetails1}
    return render(request, 'doc/patient_list_app_appointment.html', context)


# Tìm kiếm lịch hẹn theo tên hoặc mã lịch hẹn
def Search_Appointments(request):
    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    if request.method == "GET":
        query = request.GET.get('query', '')
        if query:
            # FIX 2: Vá Lỗ hổng Logic dữ liệu bằng Q Objects
            # Logic cũ không có dấu ngoặc () nên sẽ bị lỗi ưu tiên toán tử AND/OR, 
            # có thể làm rò rỉ lịch hẹn của Bác sĩ khác. 
            # Dùng Q() object giúp khóa chặt điều kiện: (Thuộc về Bác Sĩ NÀY) VÀ (Tên HOẶC Mã khớp query)
            patient = Appointment.objects.filter(
                Q(doctor_id=doctor_reg) & 
                (Q(fullname__icontains=query) | Q(appointmentnumber__icontains=query))
            ).order_by('-id')

            messages.success(request, "Search against " + query)
            return render(request, 'doc/search-appointment.html', {'patient': patient, 'query': query})
        else:
            return render(request, 'doc/search-appointment.html', {})


# Báo cáo lịch hẹn theo khoảng ngày
def Between_Date_Report(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    patient = []

    doctor_admin = request.user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return render(request, 'doc/between-dates-report.html', {'error_message': 'Invalid date format'})

        # FIX 3: Viết gộp điều kiện filter cho an toàn và hiệu suất cao hơn thay vì dùng toán tử &
        # Đồng thời thêm order_by('-id')
        patient = Appointment.objects.filter(
            doctor_id=doctor_reg,
            created_at__range=(start_date, end_date)
        ).order_by('-id')

    return render(request, 'doc/between-dates-report.html', {'patient': patient, 'start_date': start_date, 'end_date': end_date})