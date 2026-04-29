from dasapp.models import CustomUser

class GatewayIntegrationMiddleware:
    """
    Middleware này đóng vai trò "phiên dịch" các thông tin bảo mật 
    từ OpenResty Gateway chuyển xuống cho Django Backend.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # =====================================================
        # 1. FIX LỖI IP: Lấy IP thật từ WAF gửi sang
        # =====================================================
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Lấy IP đầu tiên trong chuỗi (IP gốc của client đã được WAF lọc)
            real_ip = x_forwarded_for.split(',')[0].strip()
            request.META['REMOTE_ADDR'] = real_ip

        # =====================================================
        # 2. FIX LỖI XÁC THỰC: Đọc User ID từ JWT Gateway
        # =====================================================
        # Nginx gửi Header "X-User-ID", Django tự động chuyển thành "HTTP_X_USER_ID"
        user_id = request.META.get('HTTP_X_USER_ID')
        
        if user_id:
            try:
                # Tìm user trong DB và gán vào request.user để bỏ qua Session mặc định
                user = CustomUser.objects.get(id=user_id)
                request.user = user
            except CustomUser.DoesNotExist:
                pass 
                
        # Nếu không có user_id từ Nginx, request.user vẫn giữ nguyên trạng thái 
        # (AnonymousUser hoặc do Session cũ) do AuthenticationMiddleware ở trên thiết lập.

        response = self.get_response(request)
        return response