from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import logout, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
import logging

from dasapp.EmailBackEnd import EmailBackEnd
from dasapp.models import CustomUser
from docappsystem.utils.ip import get_client_ip  # 👈 NEW

logger = logging.getLogger(__name__)
User = get_user_model()

def get_client_ip(request):
    return request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR")

# ================= BASE =================
def BASE(request):
    return render(request, 'base.html')


# ================= LOGIN =================
def LOGIN(request):
    return render(request, 'login.html')


def doLogin(request):
    if request.method != 'POST':
        messages.error(request, 'Invalid request method')
        return redirect('login')

    email = request.POST.get('email')
    password = request.POST.get('password')

    if not email or not password:
        messages.error(request, 'Missing credentials')
        return redirect('login')

    ip = get_client_ip(request)

    user = EmailBackEnd.authenticate(
        request,
        username=email,
        password=password
    )

    if user:
        login(request, user)

        logger.info(f"[LOGIN SUCCESS] user={email} ip={ip}")

        if user.user_type == '1':
            return redirect('admin_home')
        elif user.user_type == '2':
            return redirect('doctor_home')
        elif user.user_type == '3':
            return HttpResponse("User panel")

    logger.warning(f"[LOGIN FAIL] user={email} ip={ip}")

    messages.error(request, 'Email or Password is not valid')
    return redirect('login')


# ================= LOGOUT =================
def doLogout(request):
    logout(request)
    return redirect('login')


# ================= PROFILE =================
@login_required(login_url='/auth/login/')
def PROFILE(request):
    user = CustomUser.objects.get(id=request.user.id)
    return render(request, 'profile.html', {"user": user})


@login_required(login_url='/auth/login/')
def PROFILE_UPDATE(request):
    if request.method != "POST":
        return redirect('profile')

    try:
        user = CustomUser.objects.get(id=request.user.id)

        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()

        profile_pic = request.FILES.get('profile_pic')

        # ✅ FILE VALIDATION
        if profile_pic:
            if profile_pic.size > 2 * 1024 * 1024:
                messages.error(request, "File too large (max 2MB)")
                return redirect('profile')

            if not profile_pic.content_type.startswith("image/"):
                messages.error(request, "Invalid file type")
                return redirect('profile')

            user.profile_pic = profile_pic

        user.save()

        messages.success(request, "Profile updated successfully")
        return redirect('profile')

    except Exception as e:
        logger.error(f"[PROFILE UPDATE ERROR] {str(e)}")
        messages.error(request, "Profile update failed")
        return redirect('profile')


# ================= CHANGE PASSWORD =================
@login_required(login_url='/auth/login/')
def CHANGE_PASSWORD(request):

    if request.method != "POST":
        return render(request, 'change-password.html')

    current = request.POST.get("cpwd")
    new_password = request.POST.get("npwd")

    if not current or not new_password:
        messages.error(request, "Missing password fields")
        return redirect("change_password")

    user = request.user

    if not user.check_password(current):
        messages.error(request, "Current password is wrong")
        return redirect("change_password")

    user.set_password(new_password)
    user.save()

    # Re-login
    login(request, user)

    messages.success(request, "Password changed successfully")
    return redirect("profile")