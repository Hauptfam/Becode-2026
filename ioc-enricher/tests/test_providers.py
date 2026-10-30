from datetime import datetime, timezone

from conftest import FakeResponse, FakeSession

from ioc_enricher.ioc import parse
from ioc_enricher.providers import RDAP, AbuseIPDB, Status, URLhaus, VirusTotal


def vt_payload(malicious=0, suspicious=0, harmless=60, **extra):
    stats = {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": 10}
    return {"data": {"attributes": {"last_analysis_stats": stats, **extra}}}


# --- generic behaviour ------------------------------------------------------------

def test_missing_key_is_skipped_without_request():
    session = FakeSession()
    result = VirusTotal(None, session=session).lookup(parse("8.8.8.8"))
    assert result.status == Status.SKIPPED
    assert session.calls == []


def test_auth_error_becomes_error_result():
    session = FakeSession({"virustotal": FakeResponse(401)})
    result = VirusTotal("bad", session=session).lookup(parse("8.8.8.8"))
    assert result.status == Status.ERROR
    assert "API key" in result.summary


def test_rate_limit_becomes_error_result():
    session = FakeSession({"virustotal": FakeResponse(429)})
    result = VirusTotal("k", session=session).lookup(parse("8.8.8.8"))
    assert result.status == Status.ERROR
    assert "rate limited" in result.summary


def test_malformed_response_becomes_error_result():
    session = FakeSession({"virustotal": FakeResponse(200, {"unexpected": True})})
    result = VirusTotal("k", session=session).lookup(parse("8.8.8.8"))
    assert result.status == Status.ERROR


# --- VirusTotal ---------------------------------------------------------------------

def test_virustotal_malicious_hash():
    payload = vt_payload(
        malicious=55, meaningful_name="eicar.com",
        popular_threat_classification={"suggested_threat_label": "eicar/test"},
    )
    session = FakeSession({"/files/": FakeResponse(200, payload)})
    result = VirusTotal("k", session=session).lookup(parse("44d88612fea8a8f36de82e1278abb02f"))
    assert result.status == Status.OK
    assert result.score == 100
    assert "55/" in result.summary and "eicar/test" in result.summary
    assert session.calls[0]["headers"]["x-apikey"] == "k"


def test_virustotal_clean_ip():
    session = FakeSession({"/ip_addresses/8.8.8.8": FakeResponse(200, vt_payload(country="US"))})
    result = VirusTotal("k", session=session).lookup(parse("8.8.8.8"))
    assert result.score == 0
    assert result.details["country"] == "US"


def test_virustotal_url_uses_unpadded_base64_id():
    session = FakeSession({"/urls/": FakeResponse(200, vt_payload(malicious=3))})
    VirusTotal("k", session=session).lookup(parse("http://evil.com/"))
    assert session.calls[0]["url"].endswith("/urls/aHR0cDovL2V2aWwuY29tLw")


def test_virustotal_not_found():
    result = VirusTotal("k", session=FakeSession()).lookup(parse("evil.com"))
    assert result.status == Status.NOT_FOUND


# --- AbuseIPDB ----------------------------------------------------------------------

def test_abuseipdb_reported_ip():
    payload = {"data": {"abuseConfidenceScore": 100, "totalReports": 2300, "countryCode": "DE", "isTor": True}}
    session = FakeSession({"abuseipdb": FakeResponse(200, payload)})
    result = AbuseIPDB("k", session=session).lookup(parse("185.220.101.4"))
    assert result.score == 100
    assert "Tor exit node" in result.summary
    assert session.calls[0]["params"]["ipAddress"] == "185.220.101.4"


def test_abuseipdb_only_supports_ips():
    provider = AbuseIPDB("k")
    assert provider.supports(parse("1.2.3.4"))
    assert not provider.supports(parse("evil.com"))


# --- URLhaus ------------------------------------------------------------------------

def test_urlhaus_online_url():
    payload = {"query_status": "ok", "url_status": "online", "threat": "malware_download",
               "tags": ["emotet", "doc"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}
    session = FakeSession({"/url/": FakeResponse(200, payload)})
    result = URLhaus("k", session=session).lookup(parse("http://evil.com/a.doc"))
    assert result.score == 95
    assert "emotet" in result.summary
    assert session.calls[0]["headers"]["Auth-Key"] == "k"


def test_urlhaus_host_with_offline_urls():
    payload = {"query_status": "ok", "url_count": "3",
               "urls": [{"url_status": "offline", "tags": ["qakbot"]}] * 3}
    session = FakeSession({"/host/": FakeResponse(200, payload)})
    result = URLhaus("k", session=session).lookup(parse("evil.com"))
    assert result.score == 70
    assert result.details["malware_urls"] == 3


def test_urlhaus_payload_and_no_results():
    hit = FakeSession({"/payload/": FakeResponse(200, {"query_status": "ok", "signature": "AgentTesla",
                                                       "sha256_hash": "ab" * 32})})
    result = URLhaus("k", session=hit).lookup(parse("ab" * 32))
    assert "AgentTesla" in result.summary
    assert hit.calls[0]["data"] == {"sha256_hash": "ab" * 32}

    miss = FakeSession({"/payload/": FakeResponse(200, {"query_status": "no_results"})})
    assert URLhaus("k", session=miss).lookup(parse("ab" * 32)).status == Status.NOT_FOUND


def test_urlhaus_does_not_support_sha1():
    assert not URLhaus("k").supports(parse("3395856ce81f2b7382dee72602f798b642f14140"))


# --- RDAP ---------------------------------------------------------------------------

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)


def rdap_domain(created: str):
    return {
        "events": [{"eventAction": "registration", "eventDate": created}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]]}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
    }


def test_rdap_flags_newly_registered_domain():
    session = FakeSession({"/domain/": FakeResponse(200, rdap_domain("2026-10-20T10:00:00Z"))})
    result = RDAP(session=session, now=NOW).lookup(parse("login-microsoft-secure.com"))
    assert result.score == 40
    assert result.details["age_days"] == 7
    assert result.details["registrar"] == "NameCheap, Inc."
    assert "newly registered" in result.summary


def test_rdap_old_domain_is_informational():
    session = FakeSession({"/domain/": FakeResponse(200, rdap_domain("1997-09-15T04:00:00Z"))})
    result = RDAP(session=session, now=NOW).lookup(parse("google.com"))
    assert result.score is None
    assert result.status == Status.OK


def test_rdap_ip_owner():
    payload = {"name": "GOGL", "country": "US", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
               "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]}
    session = FakeSession({"/ip/": FakeResponse(200, payload)})
    result = RDAP(session=session).lookup(parse("8.8.8.8"))
    assert result.summary == "Google LLC, US"


def test_rdap_needs_no_key():
    session = FakeSession({"/ip/": FakeResponse(200, {"name": "NET"})})
    assert RDAP(session=session).lookup(parse("8.8.8.8")).status == Status.OK
