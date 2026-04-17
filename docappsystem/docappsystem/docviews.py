# Import các hàm render giao diện, chuyển hướng và trả về HTTP response
from multiprocessing import context
from django.shortcuts import render,redirect,HttpResponse

# Decorator yêu cầu người dùng phải đăng nhập mới được truy cập view
from django.contrib.auth.decorators import login_required

# Import các model từ app dasapp
# DoctorReg: thông tin bác sĩ
# Specialization: chuyên khoa
# CustomUser: user tùy chỉnh (bác sĩ, bệnh nhân, admin)
# Appointment: lịch hẹn
from dasapp.models import DoctorReg,Specialization,CustomUser,Appointment

# Import hệ thống message để hiển thị thông báo (success, warning, error)
from django.contrib import messages

# Import thư viện phân trang
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# Import datetime để xử lý ngày tháng
from datetime import datetime

# View đăng ký bác sĩ
def DOCSIGNUP(request):

    # Lấy tất cả danh sách chuyên khoa để hiển thị trên form đăng ký
    specialization = Specialization.objects.all()

    # Kiểm tra nếu form được submit bằng phương thức POST
    if request.method == "POST":

        # Lấy file ảnh từ form upload
        pic = request.FILES.get('pic')

        # Lấy dữ liệu từ form
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        mobno = request.POST.get('mobno')
        specialization_id = request.POST.get('specialization_id')
        password = request.POST.get('password')

        # Kiểm tra email đã tồn tại chưa (quan trọng để tránh trùng user)
        if CustomUser.objects.filter(email=email).exists():
            messages.warning(request,'Email already exist')
            return redirect('docsignup')

        # Kiểm tra username đã tồn tại chưa
        if CustomUser.objects.filter(username=username).exists():
            messages.warning(request,'Username already exist')
            return redirect('docsignup')

        else:

            # Tạo user mới với user_type = 2 (QUAN TRỌNG: 2 = bác sĩ)
            user = CustomUser(
               first_name=first_name,
               last_name=last_name,
               username=username,
               email=email,

               # QUAN TRỌNG:
               # user_type dùng để phân biệt loại user:
               # 1 = admin
               # 2 = doctor
               # 3 = patient
               user_type=2,

               profile_pic = pic,
            )

            # QUAN TRỌNG:
            # set_password sẽ hash mật khẩu trước khi lưu (không lưu plain text)
            user.set_password(password)

            # Lưu user vào database
            user.save()

            # Lấy specialization object từ specialization_id
            spid =Specialization.objects.get(id=specialization_id)

            # Tạo bản ghi bác sĩ trong bảng DoctorReg
            doctor = DoctorReg(

                # QUAN TRỌNG:
                # admin là khóa ngoại liên kết tới CustomUser
                admin = user,

                mobilenumber = mobno,

                # specialization_id là khóa ngoại tới bảng Specialization
                specialization_id = spid,

            )

            # Lưu thông tin bác sĩ
            doctor.save()

            messages.success(request,'Signup Successfully')

            return redirect('docsignup')

    # Truyền specialization sang template
    context = {
        'specialization':specialization
    }

    return render(request,'doc/docreg.html',context)

# Trang dashboard chính của bác sĩ
# login_required đảm bảo chỉ bác sĩ đăng nhập mới truy cập được
@login_required(login_url='/')
def DOCTORHOME(request):

    # Lấy user hiện tại đang đăng nhập
    doctor_admin = request.user

    # Lấy thông tin DoctorReg tương ứng với user
    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    # Đếm tổng số lịch hẹn của bác sĩ
    # QUAN TRỌNG: filter theo doctor_id để mỗi bác sĩ chỉ thấy lịch của mình
    allaptcount = Appointment.objects.filter(doctor_id=doctor_reg).count

    # Đếm lịch hẹn mới (status = '0')
    newaptcount = Appointment.objects.filter(status='0',doctor_id=doctor_reg).count

    # Đếm lịch hẹn đã duyệt
    appaptcount = Appointment.objects.filter(status='Approved',doctor_id=doctor_reg).count

    # Đếm lịch hẹn đã hủy
    canaptcount = Appointment.objects.filter(status='Cancelled',doctor_id=doctor_reg).count

    # Đếm lịch hẹn đã hoàn thành
    comaptcount = Appointment.objects.filter(status='Completed',doctor_id=doctor_reg).count

    context = {
        'newaptcount':newaptcount,
        'allaptcount':allaptcount,
        'appaptcount':appaptcount,
        'canaptcount':canaptcount,
        'comaptcount':comaptcount
    }

    return render(request,'doc/dochome.html',context)

# Xem danh sách lịch hẹn của bác sĩ
def View_Appointment(request):

    try:

        # Lấy bác sĩ hiện tại
        doctor_admin = request.user

        # Lấy DoctorReg tương ứng
        doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

        # Lấy tất cả lịch hẹn của bác sĩ
        view_appointment = Appointment.objects.filter(doctor_id=doctor_reg)

        # PHÂN TRANG (QUAN TRỌNG)
        # Chia danh sách lịch hẹn thành từng trang, mỗi trang 5 lịch hẹn
        paginator = Paginator(view_appointment, 5)

        # Lấy số trang từ URL (?page=2)
        page = request.GET.get('page')

        try:

            # Lấy dữ liệu của trang tương ứng
            view_appointment = paginator.page(page)

        except PageNotAnInteger:

            # Nếu page không phải số, hiển thị trang đầu
            view_appointment = paginator.page(1)

        except EmptyPage:

            # Nếu page vượt quá số trang, hiển thị trang cuối
            view_appointment = paginator.page(paginator.num_pages)

        context = {'view_appointment': view_appointment}

    except Exception as e:

        # Xử lý lỗi (ví dụ lỗi database)
        context = {'error_message': str(e)}

    return render(request, 'doc/view_appointment.html', context)

# Xem chi tiết lịch hẹn của bệnh nhân
def Patient_Appointment_Details(request,id):

    # Lấy lịch hẹn theo id
    patientdetails=Appointment.objects.filter(id=id)

    context={'patientdetails':patientdetails}

    return render(request,'doc/patient_appointment_details.html',context)

# Cập nhật trạng thái lịch hẹn và ghi chú
def Patient_Appointment_Details_Remark(request):

    if request.method == 'POST':

        # Lấy id lịch hẹn
        patient_id = request.POST.get('pat_id')

        # Lấy ghi chú của bác sĩ
        remark = request.POST['remark']

        # Lấy trạng thái mới
        status = request.POST['status']

        # Lấy appointment từ database
        patientaptdet = Appointment.objects.get(id=patient_id)

        # Cập nhật remark
        patientaptdet.remark = remark

        # Cập nhật status
        patientaptdet.status = status

        # Lưu thay đổi
        patientaptdet.save()

        messages.success(request,"Status Update successfully")

        return redirect('view_appointment')

    return render(request,'doc/view_appointment.html', context)

# Xem danh sách lịch hẹn đã duyệt
def Patient_Approved_Appointment(request):

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    # Filter lịch hẹn theo status và doctor
    patientdetails1 = Appointment.objects.filter(status='Approved',doctor_id=doctor_reg)

    context = {'patientdetails1': patientdetails1}

    return render(request, 'doc/patient_app_appointment.html', context)

# Xem danh sách lịch hẹn đã hủy
def Patient_Cancelled_Appointment(request):

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    patientdetails1 = Appointment.objects.filter(status='Cancelled',doctor_id=doctor_reg)

    context = {'patientdetails1': patientdetails1}

    return render(request, 'doc/patient_app_appointment.html', context)

# Xem danh sách lịch hẹn mới
def Patient_New_Appointment(request):

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    patientdetails1 = Appointment.objects.filter(status='0',doctor_id=doctor_reg)

    context = {'patientdetails1': patientdetails1}

    return render(request, 'doc/patient_app_appointment.html', context)

# Xem danh sách lịch hẹn đã duyệt (dạng list khác)
def Patient_List_Approved_Appointment(request):

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    patientdetails1 = Appointment.objects.filter(status='Approved',doctor_id=doctor_reg)

    context = {'patientdetails1': patientdetails1}

    return render(request, 'doc/patient_list_app_appointment.html', context)

# Xem chi tiết lịch hẹn
def DoctorAppointmentList(request,id):

    patientdetails=Appointment.objects.filter(id=id)

    context={'patientdetails':patientdetails}

    return render(request,'doc/doctor_appointment_list_details.html',context)

# Cập nhật đơn thuốc và xét nghiệm
def Patient_Appointment_Prescription(request):

    if request.method == 'POST':

        patient_id = request.POST.get('pat_id')

        prescription = request.POST['prescription']

        recommendedtest = request.POST['recommendedtest']

        status = request.POST['status']

        patientaptdet = Appointment.objects.get(id=patient_id)

        # Lưu đơn thuốc
        patientaptdet.prescription = prescription

        # Lưu xét nghiệm đề nghị
        patientaptdet.recommendedtest = recommendedtest

        # Cập nhật trạng thái
        patientaptdet.status = status

        patientaptdet.save()

        messages.success(request,"Status Update successfully")

        return redirect('view_appointment')

    return render(request,'doc/patient_list_app_appointment.html',context)

# Xem lịch hẹn đã hoàn thành
def Patient_Appointment_Completed(request):

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    patientdetails1 = Appointment.objects.filter(status='Completed',doctor_id=doctor_reg)

    context = {'patientdetails1': patientdetails1}

    return render(request, 'doc/patient_list_app_appointment.html', context)

# Tìm kiếm lịch hẹn theo tên hoặc mã lịch hẹn
def Search_Appointments(request):

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    if request.method == "GET":

        query = request.GET.get('query', '')

        if query:

            # QUAN TRỌNG:
            # icontains = tìm kiếm không phân biệt chữ hoa chữ thường
            patient = Appointment.objects.filter(fullname__icontains=query) | Appointment.objects.filter(appointmentnumber__icontains=query) & Appointment.objects.filter(doctor_id=doctor_reg)

            messages.success(request, "Search against " + query)

            return render(request, 'doc/search-appointment.html', {'patient': patient, 'query': query})

        else:

            print("No Record Found")

            return render(request, 'doc/search-appointment.html', {})

# Báo cáo lịch hẹn theo khoảng ngày
def Between_Date_Report(request):

    start_date = request.GET.get('start_date')

    end_date = request.GET.get('end_date')

    patient = []

    doctor_admin = request.user

    doctor_reg = DoctorReg.objects.get(admin=doctor_admin)

    if start_date and end_date:

        # QUAN TRỌNG:
        # Chuyển string sang datetime object
        try:

            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()

            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

        except ValueError:

            return render(request, 'doc/between-dates-report.html', {'error_message': 'Invalid date format'})

        # Filter lịch hẹn trong khoảng ngày
        patient = Appointment.objects.filter(created_at__range=(start_date, end_date)) & Appointment.objects.filter(doctor_id=doctor_reg)

    return render(request, 'doc/between-dates-report.html', {'patient': patient,'start_date':start_date,'end_date':end_date})
