from celery import shared_task
from datetime import timedelta
from django.utils import timezone
from ip_tracking.models import SuspiciousIP, RequestLog
from django.db.models import Count

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_ips():
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # This counts requests per IP in the past hour
    ip_counts = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in ip_counts:
        ip = entry['ip_address']
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason="Over 100 requests/hour")

    # Find IPs that accessed sensitive paths
    for path in SENSITIVE_PATHS:
        suspicious_logs = (
            RequestLog.objects
            .filter(timestamp__gte=one_hour_ago, path=path)
            .values('ip_address')
            .distinct()
        )

        for entry in suspicious_logs:
            ip = entry['ip_address']
            SuspiciousIP.objects.get_or_create(ip_address=ip, reason=f"Accessed sensitive path {path}")
