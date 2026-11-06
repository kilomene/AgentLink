"""v2.0.3 pins: the parked-work restore sweep (v1.3.1 parity).

migration-v200-cron.sql parks open work as 'awaiting_agent' when
its assignee is confirmed offline; without a flip-back the work
is parked FOREVER (no Edge route performs awaiting_agent ->
assigned). The v203 migration must carry the restore sweep in
the same activeness family: assignee mirror 'online' again ->
their awaiting_agent work returns to 'assigned', unchanged.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "supabase" / "migration-v203-work-restore.sql").read_text()


def test_restore_function_exists_and_flips_only_parked_rows():
    assert "create or replace function public.al_sweep_activeness_restore()" in SQL
    m = re.search(
        r"function public\.al_sweep_activeness_restore.*?language plpgsql",
        SQL, re.S)
    assert m, "restore function definition not found"
    body = SQL[m.start():]
    assert "set status = 'assigned'" in body
    assert "w.status = 'awaiting_agent'" in body


def test_restore_keys_on_the_assignees_online_mirror():
    assert "a.username = w.assignee" in SQL
    assert "a.state = 'online'" in SQL


def test_restore_is_scheduled_with_the_activeness_family():
    assert "cron.unschedule" in SQL  # unschedule-first idempotence
    assert ("cron.schedule('agentlink-v200-restore-sweep', '* * * * *',"
            in SQL)
    assert "'select al_sweep_activeness_restore()'" in SQL
