"""Saudi PDPL authority-notice clock. The server's local time is the clock."""

from datetime import datetime, timedelta

NOTICE_HOURS = 72


def notice_window(discovered_at: datetime, now: datetime) -> str:
    if now - discovered_at <= timedelta(hours=NOTICE_HOURS):
        return "Inside the 72-hour notice window"
    return "Past the 72-hour notice window"
