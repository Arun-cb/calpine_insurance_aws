from django.utils.deprecation import MiddlewareMixin
import threading

# Thread-local storage for audit context
audit_context = threading.local()

class AuditMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Set window name from request path
        audit_context.windowname = request.path
        # print(f"==>> request: {request.data}")
        
        # Safely get user ID (works for both authenticated and anonymous users)
        user = getattr(request, 'user', None)
        audit_context.last_updated_by = user.id if (user and user.is_authenticated) else None

    def process_response(self, request, response):
        # Cleanup context after request
        if hasattr(audit_context, 'windowname'):
            del audit_context.windowname
        if hasattr(audit_context, 'last_updated_by'):
            del audit_context.last_updated_by
        return response