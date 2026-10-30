import pytest

from ioc_enricher.ioc import IOCType, defang, detect_type, extract, parse, refang


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IOCType.IPV4),
        ("2001:4860:4860::8888", IOCType.IPV6),
        ("example.com", IOCType.DOMAIN),
        ("sub.domain.co.uk", IOCType.DOMAIN),
        ("https://example.com/path?q=1", IOCType.URL),
        ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ("3395856ce81f2b7382dee72602f798b642f14140", IOCType.SHA1),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.SHA256),
    ],
)
def test_detect_type(value, expected):
    assert detect_type(value) == expected


@pytest.mark.parametrize("value", ["", "hello", "999.1.1.1", "abc123", "not a domain", "-bad.com"])
def test_detect_type_rejects_garbage(value):
    assert detect_type(value) is None


@pytest.mark.parametrize(
    ("defanged", "real"),
    [
        ("hxxp://evil[.]com/a", "http://evil.com/a"),
        ("hxxps[://]evil[.]com", "https://evil.com"),
        ("evil(.)com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("1.2.3[.]4", "1.2.3.4"),
        ("  'evil[.]com', ", "evil.com"),
    ],
)
def test_refang(defanged, real):
    assert refang(defanged) == real


def test_defang_url_only_touches_host():
    assert defang("https://evil.com/file.exe", IOCType.URL) == "hxxps://evil[.]com/file.exe"


def test_defang_ip_and_domain():
    assert defang("1.2.3.4", IOCType.IPV4) == "1[.]2[.]3[.]4"
    assert defang("evil.com", IOCType.DOMAIN) == "evil[.]com"


def test_defang_leaves_hashes_alone():
    h = "44d88612fea8a8f36de82e1278abb02f"
    assert defang(h, IOCType.MD5) == h


def test_parse_normalises():
    assert parse("EVIL[.]COM").value == "evil.com"
    assert parse("44D88612FEA8A8F36DE82E1278ABB02F").value == "44d88612fea8a8f36de82e1278abb02f"
    assert parse("2001:0db8:0000:0000:0000:0000:0000:0001").value == "2001:db8::1"


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "172.16.4.2", "fe80::1"])
def test_private_ips(ip):
    assert parse(ip).is_private


def test_public_ip_is_not_private():
    assert not parse("8.8.8.8").is_private


def test_url_host():
    assert parse("hxxps://user@Evil[.]com:8443/x").host == "evil.com"


def test_extract_from_report():
    text = (
        "Beacon to 185[.]220[.]101[.]4 then GET hxxp://bad-site[.]ru/stage2.ps1 (stage 2).\n"
        "Dropped invoice.pdf.exe, sha256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.\n"
        "Phishing from login-microsoft-secure[.]com, again login-microsoft-secure.com."
    )
    found = [(i.type, i.value) for i in extract(text)]
    assert found == [
        (IOCType.IPV4, "185.220.101.4"),
        (IOCType.URL, "http://bad-site.ru/stage2.ps1"),
        (IOCType.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (IOCType.DOMAIN, "login-microsoft-secure.com"),
    ]


def test_extract_ignores_filenames():
    assert extract("ran payload.exe and notes.txt via script.ps1") == []
