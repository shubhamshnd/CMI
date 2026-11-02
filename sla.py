"""SLA clocks: respond / resolve targets from SlaRule, counted in office hours (or 24x7), paused while the ticket waits
on someone outside IT. Pure functions of the ticket's status history, so nothing has to be kept in step."""
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta

from flask import current_app

from models import utcnow

PAUSED = {"Pending Approval", "Returned", "On Hold"}  # waiting on approvers, the requester, or a supplier
STOPPED = {"Closed", "Rejected"}
WARN_AT = 0.75
DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass
class Calendar:
    start: time
    end: time
    days: set  # weekday numbers, Monday = 0
    holidays: set  # dates
    offset: timedelta  # local time - UTC; ponytail: fixed offset (IST has no DST), use zoneinfo if a DST zone is needed

    @property
    def day_minutes(self):
        return (datetime.combine(date.min, self.end) - datetime.combine(date.min, self.start)).total_seconds() / 60


def calendar():
    cfg = current_app.config
    start, end = (time.fromisoformat(x.strip()) for x in cfg["OFFICE_HOURS"].split("-"))
    return Calendar(start, end, {DAY_NAMES.index(d.strip()[:3].title()) for d in cfg["OFFICE_DAYS"].split(",") if d.strip()},
                    {date.fromisoformat(d.strip()) for d in cfg["HOLIDAYS"].split(",") if d.strip()},
                    timedelta(minutes=cfg["UTC_OFFSET_MINUTES"]))


def working_minutes(a, b, cal, round_the_clock=False):
    """Minutes between UTC datetimes a and b that count towards an SLA."""
    if b <= a:
        return 0
    if round_the_clock:
        return (b - a).total_seconds() / 60
    a, b = a + cal.offset, b + cal.offset
    total, day = 0, a.date()
    while day <= b.date():
        if day.weekday() in cal.days and day not in cal.holidays:
            s, e = max(a, datetime.combine(day, cal.start)), min(b, datetime.combine(day, cal.end))
            if e > s:
                total += (e - s).total_seconds() / 60
        day += timedelta(days=1)
    return total


def add_working(start, minutes, cal, round_the_clock=False):
    """UTC time when `minutes` countable minutes have passed after `start`."""
    if round_the_clock:
        return start + timedelta(minutes=minutes)
    local, left = start + cal.offset, minutes
    day = local.date()
    for _ in range(3660):  # ten years of days: a calendar with no working days must not loop forever
        if day.weekday() in cal.days and day not in cal.holidays:
            s, e = max(local, datetime.combine(day, cal.start)), datetime.combine(day, cal.end)
            if e > s:
                avail = (e - s).total_seconds() / 60
                if left <= avail:
                    return s + timedelta(minutes=left) - cal.offset
                left -= avail
        day += timedelta(days=1)
    return None


def running_intervals(t, until):
    """[(from, to)] in which the ticket's clock ran: not paused and not closed, up to `until`."""
    changes = sorted((h.at, h.new) for h in t.history if h.field == "status")
    out, status, since = [], "New", t.created_at
    for at, new in [*changes, (until, None)]:
        at = min(at, until)
        if status not in PAUSED | STOPPED and at > since:
            out.append((since, at))
        if new is None or at >= until:
            break
        status, since = new, at
    return out


def parse_duration(text, cal, round_the_clock=False):
    """'30m', '4h', '2d' (a day is one office day, or 24 h for 24x7 rules) -> minutes; '' -> None."""
    text = (text or "").strip().lower()
    if not text:
        return None
    unit = {"m": 1, "h": 60, "d": 1440 if round_the_clock else cal.day_minutes}.get(text[-1])
    if not unit:
        raise ValueError(text)
    value = float(text[:-1])
    if value <= 0:
        raise ValueError(text)
    return round(value * unit)


def format_duration(minutes, cal=None, round_the_clock=False):
    if minutes is None:
        return ""
    day = 1440 if round_the_clock or not cal else cal.day_minutes
    if minutes >= day and minutes % day == 0:
        return f"{int(minutes // day)}d"
    return f"{minutes / 60:g}h" if minutes % 60 == 0 or minutes >= 60 else f"{int(minutes)}m"


def rule_for(t, rules):
    """Most specific rule: form + priority, form, section + priority, then section."""
    form_id = t.form_version.form_id
    best, score = None, -1
    for r in rules:
        if (r.form_id not in (None, form_id) or r.priority not in (None, t.priority)
                or (r.form_id is None and r.section_id != t.section_id)):
            continue
        s = 2 * (r.form_id is not None) + (r.priority is not None)
        if s > score:
            best, score = r, s
    return best


@dataclass
class Clock:
    kind: str  # respond | resolve
    target: float  # minutes
    used: float  # countable minutes so far
    done: bool  # responded / resolved (or the ticket was rejected)
    paused: bool
    due: datetime = None  # UTC, when running

    @property
    def ratio(self):
        return self.used / self.target if self.target else 0

    @property
    def state(self):
        if self.done:
            return "missed" if self.used > self.target else "met"
        if self.used >= self.target:
            return "breached"
        return "paused" if self.paused else "warning" if self.ratio >= WARN_AT else "running"

    @property
    def left(self):
        return self.target - self.used


def clocks(t, rules, cal, now=None):
    """{'respond': Clock, 'resolve': Clock} for the ticket's SLA rule; missing keys = no target."""
    rule = rule_for(t, rules)
    if not rule:
        return {}
    now = now or utcnow()
    stopped_at = next((h.at for h in sorted(t.history, key=lambda h: h.at, reverse=True) if h.field == "status"),
                      t.created_at) if t.status in STOPPED else None
    out = {}
    for kind, target, end, done in (
            ("respond", rule.respond_minutes, t.responded_at, bool(t.responded_at) or t.status == "Rejected"),
            ("resolve", rule.resolve_minutes, stopped_at, t.status in STOPPED)):
        if not target:
            continue
        until = end or stopped_at or now
        used = sum(working_minutes(a, b, cal, rule.round_the_clock) for a, b in running_intervals(t, until))
        paused = t.status in PAUSED
        c = Clock(kind, target, used, done, paused)
        if not done and not paused and used < target:
            c.due = add_working(now, target - used, cal, rule.round_the_clock)
        out[kind] = c
    return out
