def get_client_ip(request) -> str | None:
    """
    Extract the client's real IP from the request.
    Accounts for X-Forwarded-For (reverse proxy).
    """
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[-1].strip()
    return request.META.get("REMOTE_ADDR")
