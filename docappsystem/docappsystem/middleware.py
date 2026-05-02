"""
docappsystem/middleware.py

GatewayIdentityMiddleware — Defense in depth layer
Đọc X-User-ID và X-User-Role được forward từ OpenResty jwt_auth.lua
→ Gán vào request để view có thể dùng mà không cần parse JWT lại

Nếu request không đi qua gateway (ví dụ nội bộ Docker network trực tiếp),
middleware này từ chối các route protected thay vì để Django xử lý tùy ý.
"""

import logging

logger = logging.getLogger("dasapp")

# Các path không cần gateway identity check
_PUBLIC_PATHS = frozenset([
    "/login/",
    "/doLogin/",
    "/health/",
    "/health",
    "/doctor/signup/",
    "/static/",
    "/media/",
    "/favicon.ico",
])


def _is_public(path: str) -> bool:
    """Trả về True nếu path không cần auth check."""
    if path in _PUBLIC_PATHS:
        return True
    # Prefix check cho /static/ và /media/
    if path.startswith(("/static/", "/media/", "/admin/")):
        return True
    return False


class GatewayIdentityMiddleware:
    """
    Đọc identity headers từ OpenResty gateway.
    Không verify JWT — gateway đã làm điều đó.
    Chỉ parse và gán vào request để views dùng.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Lấy identity từ header được gateway inject
        user_id_str = request.META.get("HTTP_X_USER_ID", "").strip()
        user_role   = request.META.get("HTTP_X_USER_ROLE", "user").strip()

        if user_id_str:
            try:
                request.gateway_user_id   = int(user_id_str)
                request.gateway_user_role = user_role
            except (ValueError, TypeError):
                logger.warning(
                    "GatewayIdentity: invalid X-User-ID header value='%s'",
                    user_id_str
                )
                request.gateway_user_id   = None
                request.gateway_user_role = None
        else:
            request.gateway_user_id   = None
            request.gateway_user_role = None

        response = self.get_response(request)
        return response
