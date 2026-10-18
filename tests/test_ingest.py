from soc_autopilot.ingest import parse_auth_line, parse_jsonl_line


def test_parse_failed_password():
    ev = parse_auth_line(
        "Sep 22 11:02:43 web01 sshd[2302]: Failed password for admin "
        "from 198.51.100.7 port 33418 ssh2"
    )
    assert ev is not None
    assert ev["action"] == "failed_password"
    assert ev["user"] == "admin"
    assert ev["src_ip"] == "198.51.100.7"
    assert ev["host"] == "web01"
    assert ev["source"] == "linux-auth"


def test_parse_invalid_user():
    ev = parse_auth_line(
        "Sep 22 11:02:44 web01 sshd[2303]: Failed password for invalid user oracle "
        "from 203.0.113.44 port 40110 ssh2"
    )
    assert ev is not None
    assert ev["action"] == "invalid_user"
    assert ev["user"] == "oracle"


def test_parse_accepted():
    ev = parse_auth_line(
        "Sep 22 08:59:01 web01 sshd[2101]: Accepted password for osama "
        "from 10.0.0.12 port 51122 ssh2"
    )
    assert ev is not None
    assert ev["action"] == "accepted_password"


def test_parse_sudo_failure():
    ev = parse_auth_line(
        "Sep 22 09:00:14 web01 sudo: pam_unix(sudo:auth): authentication failure; "
        "logname=osama uid=1000 euid=0 tty=/dev/pts/0 ruser=osama rhost=  user=osama"
    )
    assert ev is not None
    assert ev["component"] == "sudo"
    assert ev["user"] == "osama"


def test_unrelated_lines_ignored():
    assert parse_auth_line("Sep 22 09:00:00 web01 systemd[1]: Started Session 3.") is None


def test_parse_jsonl_line():
    ev = parse_jsonl_line(
        '{"ts": "2026-09-22T06:00:01", "event_type": "dns_query", "qname": "a.example"}'
    )
    assert ev is not None
    assert ev["event_type"] == "dns_query"
    assert ev["ts"].year == 2026
