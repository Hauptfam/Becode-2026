"""The seven frameworks: what they are, whether they apply, what each referenced article means,
and the organisational requirements a code scan cannot verify.

Facts checked on 31 October 2026. Laws change: review this file before relying on a report.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Framework:
    key: str
    name: str
    full_name: str
    kind: str                      # "EU directive", "EU regulation", "International standard"
    applies_to: str
    key_dates: list[str]
    applicability: str = ""        # filled in by assess_applicability()
    applicability_level: str = ""  # "Applies", "Indirect", "Voluntary", "Likely out of scope", "Not applicable"
    references: dict[str, str] = field(default_factory=dict)


FRAMEWORKS: dict[str, Framework] = {
    "NIS2": Framework(
        "NIS2", "NIS2", "Directive (EU) 2022/2555 on a high common level of cybersecurity across the Union",
        "EU directive (national law: Belgian NIS2 Act of 26 April 2024)",
        "Essential and important entities in the sectors of Annexes I and II (energy, transport, banking, health, "
        "digital infrastructure, ICT service management, ...), usually medium and large organisations.",
        ["17 Oct 2024: transposition deadline; Belgian law in force since 18 Oct 2024",
         "18 Apr 2026: Belgian essential entities had to show CyberFundamentals or ISO 27001 progress (CCB)",
         "Incident reporting: 24 h early warning, 72 h notification, final report within 1 month (Art. 23)"],
        references={
            "Art. 12": "Coordinated vulnerability disclosure",
            "Art. 21(1)": "Appropriate and proportionate risk-management measures",
            "Art. 21(2)(a)": "Policies on risk analysis and information system security",
            "Art. 21(2)(b)": "Incident handling",
            "Art. 21(2)(c)": "Business continuity, backup management and disaster recovery",
            "Art. 21(2)(d)": "Supply chain security",
            "Art. 21(2)(e)": "Security in acquisition, development and maintenance, incl. vulnerability handling and disclosure",
            "Art. 21(2)(f)": "Assessing the effectiveness of cybersecurity measures",
            "Art. 21(2)(g)": "Basic cyber hygiene practices and cybersecurity training",
            "Art. 21(2)(h)": "Cryptography and, where appropriate, encryption",
            "Art. 21(2)(i)": "Human resources security, access control and asset management",
            "Art. 21(2)(j)": "Multi-factor authentication and secured communications",
            "Art. 23": "Reporting obligations for significant incidents",
        },
    ),
    "DORA": Framework(
        "DORA", "DORA", "Regulation (EU) 2022/2554 on digital operational resilience for the financial sector",
        "EU regulation",
        "Financial entities (banks, insurers, investment firms, payment institutions, crypto-asset providers, ...) "
        "and critical ICT third-party service providers.",
        ["17 Jan 2025: applies in full",
         "Major ICT incidents: initial notification within 4 h of classification (max 24 h from detection), "
         "intermediate report within 72 h, final report within 1 month"],
        references={
            "Art. 6": "ICT risk management framework",
            "Art. 8": "Identification of ICT assets, dependencies and risks",
            "Art. 9": "Protection and prevention",
            "Art. 10": "Detection of anomalous activities",
            "Art. 11": "Response and recovery",
            "Art. 12": "Backup policies, restoration and recovery",
            "Art. 17": "ICT-related incident management process",
            "Art. 19": "Reporting of major ICT-related incidents",
            "Art. 25": "Testing of ICT tools and systems",
            "Art. 28": "Managing ICT third-party risk",
        },
    ),
    "CRA": Framework(
        "CRA", "Cyber Resilience Act", "Regulation (EU) 2024/2847 on horizontal cybersecurity requirements for "
        "products with digital elements", "EU regulation",
        "Manufacturers, importers and distributors of products with digital elements (hardware and software) made "
        "available on the EU market in the course of a commercial activity.",
        ["10 Dec 2024: entered into force",
         "11 Sep 2026: reporting obligations apply (Art. 14): actively exploited vulnerabilities and severe "
         "incidents, 24 h early warning, 72 h notification, final report",
         "11 Dec 2027: all obligations apply (essential requirements, conformity assessment, CE marking)"],
        references={
            "Art. 13(2)": "Cybersecurity risk assessment of the product",
            "Art. 13(8)": "Support period (at least 5 years unless the product is expected to be used for less)",
            "Art. 13(17)": "Single point of contact for vulnerability reports",
            "Art. 14": "Reporting of actively exploited vulnerabilities and severe incidents",
            "Annex I, Part I(2)(a)": "Made available without known exploitable vulnerabilities",
            "Annex I, Part I(2)(b)": "Secure-by-default configuration",
            "Annex I, Part I(2)(c)": "Vulnerabilities can be addressed through security updates",
            "Annex I, Part I(2)(d)": "Protection from unauthorised access (authentication, access management)",
            "Annex I, Part I(2)(e)": "Confidentiality of stored and transmitted data (e.g. encryption)",
            "Annex I, Part I(2)(f)": "Integrity of data, commands and programs",
            "Annex I, Part I(2)(g)": "Data minimisation",
            "Annex I, Part I(2)(h)": "Availability of essential functions",
            "Annex I, Part I(2)(j)": "Limiting attack surfaces",
            "Annex I, Part I(2)(k)": "Reducing the impact of an incident (exploitation mitigation)",
            "Annex I, Part I(2)(l)": "Recording and monitoring of security-relevant internal activity",
            "Annex I, Part I(2)(m)": "Secure and easy removal of data and settings",
            "Annex I, Part II(1)": "Identify and document vulnerabilities and components, incl. an SBOM",
            "Annex I, Part II(2)": "Address and remediate vulnerabilities without delay",
            "Annex I, Part II(3)": "Regular tests and reviews of security",
            "Annex I, Part II(4)": "Publicly disclose fixed vulnerabilities",
            "Annex I, Part II(5)": "Coordinated vulnerability disclosure policy",
            "Annex I, Part II(6)": "Contact address for reporting vulnerabilities",
            "Annex II": "Information and instructions for the user",
            "Annex VII": "Technical documentation",
        },
    ),
    "ISO27001": Framework(
        "ISO27001", "ISO/IEC 27001:2022", "Information security management systems: requirements",
        "International standard (voluntary, certifiable)",
        "Any organisation that wants a certified information security management system (ISMS). "
        "Annex A lists 93 controls in 4 themes.",
        ["31 Oct 2025: end of the transition period from the 2013 edition",
         "Recognised path for Belgian NIS2 compliance (CCB)"],
        references={
            "6.1.2": "Information security risk assessment", "6.1.3": "Information security risk treatment",
            "8.2": "Performing risk assessments",
            "A.5.9": "Inventory of information and other associated assets", "A.5.14": "Information transfer",
            "A.5.15": "Access control", "A.5.17": "Authentication information",
            "A.5.19": "Information security in supplier relationships", "A.5.21": "Managing security in the ICT supply chain",
            "A.5.24": "Incident management planning and preparation", "A.5.26": "Response to information security incidents",
            "A.5.32": "Intellectual property rights", "A.5.33": "Protection of records",
            "A.5.34": "Privacy and protection of PII", "A.5.37": "Documented operating procedures",
            "A.8.2": "Privileged access rights", "A.8.3": "Information access restriction",
            "A.8.5": "Secure authentication", "A.8.8": "Management of technical vulnerabilities",
            "A.8.9": "Configuration management", "A.8.10": "Information deletion", "A.8.11": "Data masking",
            "A.8.12": "Data leakage prevention", "A.8.13": "Information backup", "A.8.15": "Logging",
            "A.8.16": "Monitoring activities", "A.8.24": "Use of cryptography",
            "A.8.25": "Secure development life cycle", "A.8.26": "Application security requirements",
            "A.8.28": "Secure coding", "A.8.29": "Security testing in development and acceptance",
            "A.8.31": "Separation of development, test and production environments",
            "A.8.32": "Change management", "A.8.33": "Test information",
        },
    ),
    "ISO27005": Framework(
        "ISO27005", "ISO/IEC 27005:2022", "Guidance on managing information security risks",
        "International standard (guidance, not certifiable)",
        "Any organisation running information security risk management, typically to support ISO 27001 "
        "clauses 6.1 and 8.",
        ["Fourth edition, October 2022, aligned with ISO 27001:2022"],
        references={
            "6": "Context establishment (risk criteria, acceptance criteria)",
            "7.2": "Identifying information security risks",
            "7.3": "Analysing information security risks (likelihood and consequences)",
            "7.4": "Evaluating information security risks",
            "8": "Information security risk treatment",
        },
    ),
    "AIACT": Framework(
        "AIACT", "AI Act", "Regulation (EU) 2024/1689 laying down harmonised rules on artificial intelligence, "
        "as amended by the Digital Omnibus on AI, Regulation (EU) 2026/1744", "EU regulation",
        "Providers and deployers of AI systems placed on the market or used in the EU.",
        ["2 Feb 2025: prohibited practices (Art. 5) and AI literacy (Art. 4) apply",
         "2 Aug 2025: general-purpose AI model obligations apply",
         "2 Aug 2026: transparency obligations (Art. 50) apply",
         "2 Dec 2027: high-risk systems of Annex III (postponed from Aug 2026 by Regulation (EU) 2026/1744)",
         "2 Aug 2028: high-risk AI in products covered by Annex I"],
        references={
            "Art. 3(1)": "Definition of an AI system",
            "Art. 4": "AI literacy",
            "Art. 5": "Prohibited AI practices",
            "Art. 6": "Classification rules for high-risk AI systems",
            "Art. 50": "Transparency obligations",
        },
    ),
    "GDPR": Framework(
        "GDPR", "GDPR", "Regulation (EU) 2016/679 on the protection of personal data", "EU regulation",
        "Anyone processing personal data of people in the EU. IP addresses, usernames, email addresses and "
        "hostnames linked to a person are personal data.",
        ["25 May 2018: applies", "Data breaches: notify the authority within 72 h (Art. 33)"],
        references={
            "Art. 5(1)(a)": "Lawfulness, fairness and transparency", "Art. 5(1)(c)": "Data minimisation",
            "Art. 5(1)(e)": "Storage limitation", "Art. 13": "Information to be provided to data subjects",
            "Art. 13(1)(e)": "Recipients of the personal data", "Art. 17": "Right to erasure",
            "Art. 25": "Data protection by design and by default", "Art. 28": "Processors",
            "Art. 30": "Records of processing activities", "Art. 32": "Security of processing",
            "Art. 33": "Notification of a breach to the supervisory authority",
            "Art. 34": "Communication of a breach to the data subject",
            "Art. 44": "General principle for transfers outside the EU",
        },
    ),
}


def assess_applicability(findings: dict, personal_data: dict) -> None:
    """Decide how each framework relates to the scanned project, from facts found in the scan."""
    ai = findings.get("AI-01")
    uses_ai = ai is not None and ai.status.value == "MANUAL"
    pd_projects = ", ".join(sorted(p or "(root)" for p in personal_data)) or "none"

    text = {
        "NIS2": ("Indirect", "The project is not an entity, so NIS2 doesn't apply to it directly. It applies to an "
                 "organisation in scope that uses these tools: their security then supports that organisation's "
                 "Art. 21 measures (supply chain, secure development, incident handling)."),
        "DORA": ("Indirect", "Only financial entities and their ICT providers are in scope. If a bank's SOC used these "
                 "tools, they would fall under its ICT risk management (Art. 6-16) and third-party risk (Art. 28-30)."),
        "CRA": ("Likely out of scope", "Free and open-source software developed or supplied outside a commercial "
                "activity is excluded (Recitals 18-19). This portfolio project isn't sold or monetised, so the CRA "
                "most likely doesn't apply. It becomes mandatory if the tools are ever sold or offered as part of a "
                "paid service, so its essential requirements are used here as a best-practice baseline."),
        "ISO27001": ("Voluntary", "A certification standard for an organisation's ISMS, not for a code repository. "
                     "The Annex A technical controls the code can show (secure development, cryptography, logging, "
                     "vulnerability management) are assessed; the management clauses 4-10 are listed as manual checks."),
        "ISO27005": ("Voluntary", "Guidance for the risk management process. The report derives a starting risk register "
                     "from the findings (clauses 7.2-7.4) and checks whether a risk assessment is documented."),
        "AIACT": (("Applies", "AI libraries or model files were found: each AI system must be classified.") if uses_ai
                  else ("Not applicable", "No AI system was found: no machine-learning or LLM library is imported or "
                        "declared, and there are no model files. The scoring is rule-based, with thresholds written by "
                        "a person, which the AI system definition (Art. 3(1)) excludes.")),
        "GDPR": ("Applies" if personal_data else "Not applicable",
                 (f"Personal data is processed by: {pd_projects}. The tools handle usernames, email addresses, IP "
                  "addresses and hostnames from logs. The test data is fictional, but GDPR applies in full as soon as "
                  "real logs are ingested. A SOC normally relies on legitimate interest for network security (Art. "
                  "6(1)(f), Recital 49).") if personal_data else "No personal data processing was found."),
    }
    for key, (level, why) in text.items():
        FRAMEWORKS[key].applicability_level = level
        FRAMEWORKS[key].applicability = why


# Requirements that depend on the organisation, not the code. They appear as a checklist in the report.
MANUAL_CHECKS: list[dict[str, str]] = [
    {"framework": "NIS2", "ref": "Art. 20", "item": "Management bodies approve the cybersecurity measures, oversee them and follow training."},
    {"framework": "NIS2", "ref": "Art. 23", "item": "A process exists to report significant incidents to the CSIRT (CCB in Belgium): 24 h, 72 h, 1 month."},
    {"framework": "NIS2", "ref": "Art. 21(2)(g)", "item": "Staff receive regular cyber hygiene and security awareness training."},
    {"framework": "DORA", "ref": "Art. 5-6", "item": "An ICT risk management framework is approved by the management body and reviewed yearly."},
    {"framework": "DORA", "ref": "Art. 28(3)", "item": "A register of information lists all contracts with ICT third-party providers (incl. the threat-intel APIs)."},
    {"framework": "DORA", "ref": "Art. 24-27", "item": "A digital operational resilience testing programme exists (TLPT every 3 years for significant entities)."},
    {"framework": "CRA", "ref": "Art. 14", "item": "If in scope: a process to notify ENISA's single reporting platform within 24 h of an actively exploited vulnerability."},
    {"framework": "CRA", "ref": "Art. 28, 32", "item": "If in scope: conformity assessment, EU declaration of conformity and CE marking before Dec 2027."},
    {"framework": "ISO27001", "ref": "Clauses 4-10", "item": "ISMS scope, information security policy, Statement of Applicability, internal audit and management review."},
    {"framework": "ISO27001", "ref": "A.6.3", "item": "Information security awareness, education and training for staff using the tools."},
    {"framework": "ISO27005", "ref": "6, 8", "item": "Risk criteria and acceptance criteria are defined; risk owners formally accept residual risks."},
    {"framework": "AIACT", "ref": "Art. 4", "item": "Only if AI is added later: support AI literacy of staff who use or operate it."},
    {"framework": "GDPR", "ref": "Art. 6", "item": "A lawful basis is identified for processing logs (usually legitimate interest, with a balancing test)."},
    {"framework": "GDPR", "ref": "Art. 30", "item": "The SIEM and enrichment processing appear in the record of processing activities."},
    {"framework": "GDPR", "ref": "Art. 35", "item": "A data protection impact assessment is done if monitoring is systematic and large-scale."},
    {"framework": "GDPR", "ref": "Art. 28, 44-46", "item": "Agreements and transfer mechanisms exist with VirusTotal, AbuseIPDB and other external services."},
]

SOURCES = [
    ("NIS2 Directive (EU) 2022/2555", "https://eur-lex.europa.eu/eli/dir/2022/2555/oj"),
    ("DORA Regulation (EU) 2022/2554", "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"),
    ("Cyber Resilience Act, Regulation (EU) 2024/2847", "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"),
    ("AI Act, Regulation (EU) 2024/1689", "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"),
    ("GDPR, Regulation (EU) 2016/679", "https://eur-lex.europa.eu/eli/reg/2016/679/oj"),
    ("CCB: NIS2 18 April 2026 deadline for essential entities",
     "https://ccb.belgium.be/news/nis2-18-april-2026-deadline-what-essential-entities-must-have-place"),
    ("Gibson Dunn: EU AI Act Omnibus agreement, postponed high-risk deadlines",
     "https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/"),
    ("Browne Jacobson: CRA reporting obligations in force",
     "https://www.brownejacobson.com/insights/cyber-resilience-act-reporting-obligations-in-force"),
    ("ISO/IEC 27001:2022", "https://www.iso.org/standard/27001"),
    ("ISO/IEC 27005:2022", "https://www.iso.org/standard/80585.html"),
]
