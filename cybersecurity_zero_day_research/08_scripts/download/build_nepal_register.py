#!/usr/bin/env python3
"""Build the Nepal public-source register (incidents, reports, indicators).

PROVENANCE / VERIFICATION LEVEL — read before use
-------------------------------------------------
Collection date: 2026-10-02. In the collection environment the egress policy
blocked direct retrieval of every Nepali host (kathmandupost.com, nta.gov.np,
nrb.org.np, npcert.org.np, ...), World Bank, ITU, DataReportal and APNIC. The
only channel available was a web-search engine, which returns the result URL,
the page title and a short extract of the page.

Every record below therefore carries
    verification_status = "search_extract_only"
meaning: the URL and title were returned by the search engine and the stated
fact appears in the search extract of that page, but the full page was NOT
opened. Before citing a value in the thesis, open the URL, confirm the value,
and change verification_status to "verified_full_text" (with the date).

Rules applied
  * nothing is inferred: fields not stated in the extract are "Unknown";
  * a publication date is recorded only when it is printed in the URL path or
    stated in the extract; otherwise "Unknown";
  * no article text is reproduced beyond a short factual evidence note;
  * claims disputed by the victim are recorded as disputed.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import ROOT, plog  # noqa: E402

RETRIEVED = "2026-10-02"
VS = "search_extract_only"
NEP = os.path.join(ROOT, "07_nepal_analysis")
EVID = os.path.join(NEP, "source_evidence")

# ---------------------------------------------------------------- sources
# id, title, publisher, url, publication_date, source_type
SOURCES = [
    ("S001", "Nepal Telecom network allegedly hacked", "The Kathmandu Post",
     "https://kathmandupost.com/money/2016/03/09/nepal-telecom-network-allegedly-hacked", "2016-03-09", "news"),
    ("S002", "NIC Asia cash stolen in cyber heist", "The Kathmandu Post",
     "https://kathmandupost.com/valley/2017/10/23/nic-asia-cash-stolen-in-cyber-heist", "2017-10-23", "news"),
    ("S003", "Nepal Bank Latest Victim in String of Global Cyber Heists", "Insurance Journal (Reuters)",
     "https://www.insurancejournal.com/news/international/2017/11/08/470686.htm", "2017-11-08", "news"),
    ("S004", "Millions stolen by ATM hackers exposes vulnerability of Nepali banks", "The Kathmandu Post",
     "https://kathmandupost.com/money/2019/09/01/millions-stolen-by-atm-hackers-exposes-vulnerability-of-nepali-banks",
     "2019-09-01", "news"),
    ("S005", "Foodmandu 50K users data leaked by a hacker", "NepaliTelecom",
     "https://www.nepalitelecom.com/2020/03/foodmandu-hack-user-data-leaked.html", "2020-03 (month from URL)", "news"),
    ("S006", "Vianet suffers data breach, leaking personal customer details online", "The Kathmandu Post",
     "https://kathmandupost.com/national/2020/04/08/vianet-suffers-data-breach-leaking-personal-customer-details-online",
     "2020-04-08", "news"),
    ("S007", "Official Statement on Data Breach Incident", "Vianet Communication Ltd.",
     "https://www.vianet.com.np/official-statement-on-data-breach-incident/", "Unknown", "organisation_statement"),
    ("S008", "Nepal Telecom Server Hacker arrested by CIB", "NepaliTelecom",
     "https://www.nepalitelecom.com/2020/07/nepal-telecom-server-hacker-arrested-cib.html", "2020-07 (month from URL)", "news"),
    ("S009", "Chinese Hackers Stole Call Details of Nepal Telecom", "ICT Frame",
     "https://ictframe.com/chinese-hackers-stole-call-details-of-nepal-telecom/", "Unknown", "news"),
    ("S010", "Singha Durbar server continues to face cyberattacks", "The Kathmandu Post",
     "https://kathmandupost.com/national/2023/01/30/singha-durbar-server-continues-to-face-cyberattacks", "2023-01-30", "news"),
    ("S011", "Cyberattack on govt servers explained: Everything you need to know", "Nepal Minute",
     "https://www.nepalminute.com/detail/1710/cyberattack-on-govt-servers-explained-everything-you-need-to-know-2023-Jan-29-221700",
     "2023-01-29", "news"),
    ("S012", "Government's main server faces cyberattacks", "The Kathmandu Post",
     "https://kathmandupost.com/national/2024/01/01/government-s-main-server-faces-cyberattacks", "2024-01-01", "news"),
    ("S013", "Election Commission Nepal Website Hacked by Captainsmok3r: Official Response and Security Measures",
     "ICT Frame", "https://ictframe.com/election-commission-nepal-website-hacked-by-captainsmok3r/", "Unknown", "news"),
    ("S014", "Case filed against 24 over Rs 35 million 'missing' from F1Soft's bank account", "Setopati",
     "https://en.setopati.com/social/164157", "Unknown", "news"),
    ("S015", "Banking Sector Targeted by Hackers, Over NPR 30 Million Stolen", "Banking News (bankingnews.com.np)",
     "https://bankingnews.com.np/2024/12/1293/", "2024-12 (month from URL)", "news"),
    ("S016", "Hacktivist Nepal", "Wikipedia",
     "https://en.wikipedia.org/wiki/Hacktivist_Nepal", "Unknown", "encyclopedia (tertiary)"),
    ("S017", "Nepal uncovers 135 compromised government email accounts after joining global breach tracker",
     "The Kathmandu Post",
     "https://kathmandupost.com/science-technology/2026/08/06/nepal-uncovers-135-compromised-government-email-accounts-after-joining-global-breach-tracker",
     "2026-08-06", "news"),
    ("S018", "Welcoming the Nepalese Government to Have I Been Pwned", "Troy Hunt (Have I Been Pwned)",
     "https://www.troyhunt.com/welcoming-the-nepalese-government-to-have-i-been-pwned/", "Unknown", "organisation_statement"),
    ("S019", "Nepal stock market halted after ransomware attack disrupts 72 brokers", "The Star (Malaysia)",
     "https://www.thestar.com.my/aseanplus/aseanplus-news/2026/09/21/nepal-stock-market-halted-after-ransomware-attack-disrupts-72-brokers",
     "2026-09-21", "news"),
    ("S020", "Ransomware attack shuts stock market as investors raise security concerns", "OnlineKhabar English",
     "https://english.onlinekhabar.com/ransomware-attack-shuts-nepse.html", "Unknown", "news"),
    ("S021", "National Cyber Security Policy, 2023 (English translation)", "Government of Nepal",
     "https://giwmscdnone.gov.np/media/pdf_upload/National%20Cyber%20Security%20Policy_English_version_dowpymd.pdf",
     "Unknown", "government_policy"),
    ("S022", "Govt approves National Cyber Security Policy 2023", "myRepublica",
     "https://myrepublica.nagariknetwork.com/news/govt-approves-national-cyber-security-policy-2023", "Unknown", "news"),
    ("S023", "Cyber Security Byelaw, 2077 (2020)", "Nepal Telecommunications Authority",
     "https://nta.gov.np/uploads/contents/Cyber-Security-Bylaw-2077-2020.pdf", "2020 (from title)", "regulation"),
    ("S024", "NTA MIS Report, Issue 206 (2082 Falgun)", "Nepal Telecommunications Authority",
     "https://nta.gov.np/uploads/contents/MIS_2082%20Falgun.pdf", "Unknown (covers end of Feb 2026 per extract)", "government_statistics"),
    ("S025", "NTA MIS Report, Issue 195 (Chaitra 2081)", "Nepal Telecommunications Authority",
     "https://nta.gov.np/uploads/contents/MIS%20_Chaitra_%E0%A5%A8%E0%A5%A6%E0%A5%AE%E0%A5%A7.pdf",
     "Unknown (covers end of Mar 2025 per extract)", "government_statistics"),
    ("S026", "NTA MIS Report, Issue 198 (Ashadh 2082)", "Nepal Telecommunications Authority",
     "https://nta.gov.np/uploads/contents/MIS_%20Ashadh_2082.pdf", "Unknown", "government_statistics"),
    ("S027", "Nepal's 4G User Base Surpasses 25.6 Million, Mobile Broadband Penetration Hits 87.9%", "MEA Tech Watch",
     "https://meatechwatch.com/2025/08/04/nepals-4g-user-base-surpasses-25-6-million-mobile-broadband-penetration-hits-87-9/",
     "2025-08-04", "news (secondary report of NTA MIS)"),
    ("S028", "Payment Systems Oversight Report 2023/24", "Nepal Rastra Bank",
     "https://www.nrb.org.np/contents/uploads/2025/01/Payment-Oversight-Report-2023-24.pdf", "2025-01 (month from URL)",
     "central_bank_report"),
    ("S029", "Payment Systems Oversight Report FY 2020/21", "Nepal Rastra Bank",
     "https://www.nrb.org.np/psd/payment-systems-oversight-report-2077-78-2020-2021/", "Unknown", "central_bank_report"),
    ("S030", "Find out how much international bandwidth ISPs bring to Nepal", "NepaliTelecom",
     "https://www.nepalitelecom.com/international-internet-bandwidth-isps-nepal", "Unknown", "news (secondary report of NTA)"),
    ("S031", "IPv6 penetration in Nepal", "APNIC Blog",
     "https://blog.apnic.net/2025/03/28/ipv6-penetration-in-nepal/", "2025-03-28", "technical_blog (RIR)"),
    ("S032", "IPv6 Internet Growing in Nepal, Ranks 3rd in South Asia", "NepaliTelecom",
     "https://www.nepalitelecom.com/2022/02/use-of-ipv6-growing-in-nepal-ranks-3rd-in-south-asia.html", "2022-02 (month from URL)",
     "news (secondary report of APNIC Labs)"),
    ("S033", "Nepal - Reports - DataReportal", "DataReportal (Kepios)",
     "https://datareportal.com/reports/tag/Nepal", "Unknown", "industry_report_index"),
    ("S034", "Nepal recorded 52 daily cybercrime cases last fiscal", "The Kathmandu Post",
     "https://kathmandupost.com/national/2025/07/22/nepal-recorded-52-daily-cybercrime-cases-last-fiscal", "2025-07-22", "news"),
    ("S035", "Over 20,500 cybercrime complaints registered in Nepal in a year", "Khabarhub",
     "https://english.khabarhub.com/2026/14/563210/", "2026 (year from URL)", "news"),
    ("S036", "Govt issues cybersecurity advisory to prevent hacking, data theft", "The Annapurna Express",
     "https://theannapurnaexpress.com/story/52129/", "Unknown", "news (reports government advisory)"),
    ("S037", "Report: Attackers Hacked Nepalese Bank's SWIFT Server", "BankInfoSecurity (ISMG)",
     "https://www.bankinfosecurity.com/report-attackers-hacked-nepalese-banks-swift-server-a-10437", "Unknown", "news"),
    ("S038", "Recurring tech failures rattle Nepal's stock market", "The Kathmandu Post",
     "https://kathmandupost.com/money/2026/09/22/recurring-tech-failures-rattle-nepal-s-stock-market", "2026-09-22", "news"),
]

# ---------------------------------------------------------------- incidents
# Only facts present in the search extract. "Unknown" otherwise.
INC = ["incident_id", "date", "year", "sector", "attack_type", "attack_vector", "target_type", "severity",
       "reported_impact", "organization_type", "source", "source_url", "publication_date", "retrieval_date",
       "evidence_notes", "source_ids", "verification_status"]
INCIDENTS = [
    ("NP-INC-001", "Unknown", "2016", "Telecom", "Data breach (claimed; disputed by victim)", "Unknown (outsourced partner ID possibly misused per victim)",
     "Telecom operator", "Unknown", "Hacker group claimed access to subscriber information; operator denied a breach",
     "State-owned telecom operator", ["S001"],
     "Group '#opnep' claimed breach of Nepal Telecom server; spokesperson denied but said an outsource partner ID might have been misused."),
    ("NP-INC-002", "Unknown", "2017", "Banking/Finance", "Fraudulent transfers via compromised SWIFT environment", "Malware (reported: SWIFT terminals used for personal email)",
     "Commercial bank", "High", "About USD 4.4 million in fraudulent transfers to accounts abroad; all but about USD 580,000 recovered (per Reuters via Insurance Journal)",
     "Commercial bank (NIC Asia Bank)", ["S002", "S003", "S037"],
     "Attack occurred during the Tihar festival (Oct 2017) per extracts; exact date not stated in extract."),
    ("NP-INC-003", "2019-08-31", "2019", "Banking/Finance", "ATM cash-out (payment switch compromise + cloned cards)", "Compromise of card payment switch (NEPS) and cloned debit cards",
     "Payment switch / ATMs", "High", "Rs 16.87 million withdrawn in Nepal (per Nepal Rastra Bank as reported); five foreign nationals arrested",
     "Interbank payment network", ["S004"],
     "Extract cites NRB: Rs 16.87 million looted between 11:00 and 16:30 on August 31."),
    ("NP-INC-004", "2020-03-07", "2020", "E-commerce", "Data breach", "Server-side vulnerability (SSRF reported)",
     "Food-delivery platform", "Unknown", "Personal data of about 50,000 users dumped (name, address, phone, email)",
     "Private company (Foodmandu)", ["S005"],
     "Extract: hacked 7 March 2020 20:15; attacker claimed 150,000 users, published 50,000 as sample."),
    ("NP-INC-005", "Unknown", "2020", "Telecom", "Data breach", "Unknown",
     "Internet service provider", "Unknown", "Customer personal details leaked; company estimated 100,000-170,000 customers affected",
     "Private ISP (Vianet Communications)", ["S006", "S007"],
     "Reported 8 April 2020; company acknowledged breach and said source was fixed."),
    ("NP-INC-006", "Unknown", "2020", "Telecom", "Unauthorised access (insider-style abuse of app server)", "Illegal access to mobile-app server",
     "Telecom operator", "Unknown", "Data packs misused and sold; one person arrested by CIB",
     "State-owned telecom operator", ["S008"], "Arrest reported July 2020."),
    ("NP-INC-007", "Unknown", "2021", "Telecom", "Data breach (call detail records offered for sale)", "Exploitation of Oracle GlassFish server (as reported)",
     "Telecom operator", "Unknown", "Subscriber call-detail records reportedly offered on dark web; server shut down",
     "State-owned telecom operator", ["S009"],
     "Year from search extract; attribution to foreign actors is the outlet's claim and is not independently verified."),
    ("NP-INC-008", "Unknown", "2023", "Government", "DDoS", "Distributed denial of service against Government Integrated Data Centre",
     "Government data centre / websites", "High", "Hundreds of government websites offline for hours; immigration/passport systems disrupted",
     "Central government", ["S010", "S011"],
     "Reported 29-30 Jan 2023 as ongoing; extracts give counts from ~400 to ~1,500 sites (inconsistent, not reconciled)."),
    ("NP-INC-009", "2024-01-01", "2024", "Government", "DDoS", "Distributed denial of service (per National Information Technology Centre)",
     "Government main server / websites", "Unknown", "Hundreds of government websites disrupted",
     "Central government", ["S012"], "Article dated 1 Jan 2024."),
    ("NP-INC-010", "2024-07-05", "2024", "Government", "Website defacement", "Unknown",
     "Election Commission website", "Unknown", "Homepage defaced; access to election information disrupted",
     "Constitutional body", ["S013"], "Defacement attributed to handle 'Captainsmok3r' per extract."),
    ("NP-INC-011", "Unknown", "2024", "Banking/Finance", "Account compromise / fraudulent withdrawal", "Stolen bank system-administrator credentials (as reported)",
     "Corporate bank account of a payment-technology firm", "High", "About Rs 34.2-35.15 million withdrawn via 500+ accounts; case filed against 24 people",
     "Private fintech company (F1Soft)", ["S014", "S015"],
     "Extract: withdrawals between 1 and 4 October; year 2024 from bankingnews URL (Dec 2024)."),
    ("NP-INC-012", "Unknown", "2025", "Government", "Website defacement (hacktivism)", "Unknown",
     "Government department websites", "Unknown", "Survey Department and Department of Customs websites defaced",
     "Central government departments", ["S016"], "Tertiary source (Wikipedia); verify against primary news before citing."),
    ("NP-INC-013", "Unknown", "2026", "Government", "Account compromise (credential exposure)", "Credentials exposed in third-party breaches",
     "Government email accounts", "Unknown", "At least 135 nepal.gov.np email addresses found in breach corpora; phishing using officials' names reported",
     "Central government", ["S017", "S018"], "Discovered after Nepal's NCSC joined Have I Been Pwned (article 6 Aug 2026)."),
    ("NP-INC-014", "Unknown", "2026", "Banking/Finance", "Ransomware", "Unknown",
     "Data-centre provider for securities brokers", "High", "Trading Management System of 72 brokers disrupted; NEPSE trading suspended",
     "Private infrastructure provider (Data Hub Pvt. Ltd.)", ["S019", "S020", "S038"],
     "Reported 21-22 Sep 2026; ransomware group and ransom demand not disclosed per extract."),
]

# ---------------------------------------------------------------- reports
REP = ["report_id", "title", "organization", "report_type", "publication_date", "year", "topic", "source_url",
       "retrieval_date", "summary_note", "source_id", "verification_status"]
REPORTS = [
    ("NP-REP-001", "S021", "government_policy", "2023", "National cybersecurity policy",
     "Cabinet approval reported 8 Aug 2023 (S022); provides for a National Cyber Security Centre and provincial CERTs."),
    ("NP-REP-002", "S023", "regulation", "2020", "Telecom/ISP cybersecurity obligations",
     "Requires licensees to submit internal security audit every 6 months, quarterly VAPT and annual IS audit."),
    ("NP-REP-003", "S024", "statistics", "2026", "Telecom/broadband statistics", "Monthly MIS report (Falgun 2082)."),
    ("NP-REP-004", "S025", "statistics", "2025", "Telecom/broadband statistics", "Monthly MIS report (Chaitra 2081)."),
    ("NP-REP-005", "S026", "statistics", "2025", "Telecom/broadband statistics", "Monthly MIS report (Ashadh 2082)."),
    ("NP-REP-006", "S028", "central_bank_report", "2024", "Digital payments", "Payment Systems Oversight Report FY 2023/24."),
    ("NP-REP-007", "S029", "central_bank_report", "2021", "Digital payments", "Payment Systems Oversight Report FY 2020/21."),
    ("NP-REP-008", "S031", "technical_blog", "2025", "IPv6 deployment", "APNIC analysis of IPv6 penetration in Nepal."),
    ("NP-REP-009", "S034", "news_of_official_statistics", "2025", "Cybercrime complaints (Nepal Police Cyber Bureau)",
     "Reports Cyber Bureau complaint statistics for FY 2081/82 (2024/25)."),
    ("NP-REP-010", "S036", "news_of_government_advisory", "Unknown", "Cybersecurity advisory",
     "Reports a government cybersecurity advisory; advisory text itself not retrieved."),
    ("NP-REP-011", "S018", "organisation_statement", "2026", "Government domain breach monitoring",
     "Have I Been Pwned onboarding of Nepalese government domains."),
]

# ---------------------------------------------------------------- indicators
IND = ["indicator_id", "indicator", "value", "unit", "reference_period", "geography", "source_organization",
       "source_title", "source_url", "publication_date", "retrieval_date", "evidence_notes", "source_id",
       "verification_status"]
INDICATORS = [
    ("NP-IND-001", "Total broadband subscriptions", 30828615, "subscriptions", "end of Feb 2026", "S024", "NTA MIS Falgun 2082 per extract"),
    ("NP-IND-002", "Mobile broadband subscriptions", 27368293, "subscriptions", "end of Feb 2026", "S024", "88.78% of broadband per extract"),
    ("NP-IND-003", "Fixed wired broadband subscriptions", 3427794, "subscriptions", "end of Feb 2026", "S024", "11.12% of broadband per extract"),
    ("NP-IND-004", "Fixed wireless broadband subscriptions", 32528, "subscriptions", "end of Feb 2026", "S024", "0.11% of broadband per extract"),
    ("NP-IND-005", "Total broadband subscriptions", 29115957, "subscriptions", "end of Mar 2025", "S025", "NTA MIS Chaitra 2081 per extract"),
    ("NP-IND-006", "Mobile broadband penetration", 87.90, "% of population", "Ashadh 2082 (mid-Jun to mid-Jul 2025)", "S027",
     "Secondary report of NTA MIS Ashadh 2082"),
    ("NP-IND-007", "4G users", 25600000, "users (approx., 'over 25.6 million')", "Ashadh 2082 (mid-Jun to mid-Jul 2025)", "S027",
     "Rounded figure as reported"),
    ("NP-IND-008", "Internet users", 16500000, "users", "start of 2025", "S033", "DataReportal Digital 2025: Nepal, per extract"),
    ("NP-IND-009", "International internet bandwidth", 1342, "Gbps", "2023", "S030", "Attributed to NTA by secondary source"),
    ("NP-IND-010", "IPv6 capability (national)", 26.02, "% of users", "as of 2022-02-01", "S032", "Secondary report of APNIC Labs measurement"),
    ("NP-IND-011", "Wallet (e-money) users", 23460000, "users", "mid-July 2024", "S028", "NRB Payment Oversight Report 2023/24 per extract"),
    ("NP-IND-012", "connectIPS users", 1280000, "users", "mid-July 2024", "S028", "NRB Payment Oversight Report 2023/24 per extract"),
    ("NP-IND-013", "Mobile banking customers", 24648846, "customers", "mid-July 2024", "S028", "Per search extract; confirm table in report"),
    ("NP-IND-014", "Cybercrime complaints to Nepal Police", 19730, "complaints", "FY 2080/81 (2023/24)", "S035", "Per extract"),
    ("NP-IND-015", "Cybercrime complaints to Nepal Police", 18926, "complaints", "FY 2081/82 (2024/25)", "S035", "Per extract"),
    ("NP-IND-016", "Cybercrime complaints to Nepal Police", 20526, "complaints", "FY 2082/83 (2025/26)", "S035",
     "Per extract (Khabarhub); fiscal year labelled 2025/26 in extract"),
    ("NP-IND-017", "Financial scam/fraud share of cybercrime complaints", 40.82, "% of complaints", "FY 2081/82 (2024/25)", "S034",
     "7,723 cases per extract"),
]


def w(path, header, rows):
    with open(path, "w", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(header)
        cw.writerows(rows)


def main():
    src = {s[0]: s for s in SOURCES}
    os.makedirs(EVID, exist_ok=True)
    # registry of sources
    w(os.path.join(NEP, "source_register.csv"),
      ["source_id", "title", "publisher", "url", "publication_date", "source_type", "retrieval_date", "verification_status"],
      [list(s) + [RETRIEVED, VS] for s in SOURCES])
    inc_rows = []
    for (iid, date, year, sector, atype, vector, target, sev, impact, orgtype, sids, note) in INCIDENTS:
        s0 = src[sids[0]]
        inc_rows.append([iid, date, year, sector, atype, vector, target, sev, impact, orgtype,
                         "; ".join(src[s][2] for s in sids), " | ".join(src[s][3] for s in sids), s0[4], RETRIEVED,
                         note, ";".join(sids), VS])
    w(os.path.join(NEP, "cyber_incidents.csv"), INC, inc_rows)
    rep_rows = []
    for rid, sid, rtype, year, topic, note in REPORTS:
        s = src[sid]
        rep_rows.append([rid, s[1], s[2], rtype, s[4], year, topic, s[3], RETRIEVED, note, sid, VS])
    w(os.path.join(NEP, "cybersecurity_reports.csv"), REP, rep_rows)
    ind_rows = []
    for iid, name, val, unit, period, sid, note in INDICATORS:
        s = src[sid]
        ind_rows.append([iid, name, val, unit, period, "Nepal", s[2], s[1], s[3], s[4], RETRIEVED, note, sid, VS])
    w(os.path.join(NEP, "digital_infrastructure.csv"), IND, ind_rows)
    # one evidence folder per source: metadata + short note, no article text
    used = {}
    for r in INCIDENTS:
        for s in r[10]:
            used.setdefault(s, []).append(r[0])
    for r in REPORTS:
        used.setdefault(r[1], []).append(r[0])
    for r in INDICATORS:
        used.setdefault(r[5], []).append(r[0])
    for sid, title, pub, url, pdate, stype in SOURCES:
        d = os.path.join(EVID, "source_" + sid[1:])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "source.md"), "w") as f:
            f.write(f"# {sid}: {title}\n\n"
                    f"- URL: {url}\n- Publisher: {pub}\n- Publication date: {pdate}\n- Source type: {stype}\n"
                    f"- Retrieved: {RETRIEVED}\n- Verification status: {VS}\n"
                    f"- Used by records: {', '.join(used.get(sid, [])) or 'none'}\n\n"
                    "Evidence: URL and title returned by a web-search engine; the cited fact appears in the\n"
                    "search extract of this page. Full text was not retrieved (host blocked by the collection\n"
                    "environment's egress policy). No copyrighted text is reproduced here.\n")
    # copies with the final names requested in the brief
    w(os.path.join(NEP, "nepal_cyber_incidents.csv"), INC, inc_rows)
    stats = [[r[0], r[1], r[2], r[3], r[4], r[6], r[8], r[13]] for r in ind_rows]
    w(os.path.join(NEP, "nepal_cybersecurity_statistics.csv"),
      ["indicator_id", "indicator", "value", "unit", "reference_period", "source_organization", "source_url",
       "verification_status"], stats)
    plog("build_nepal_register.py", "build", "Nepal", "web-search extracts", "07_nepal_analysis/",
         "", len(INCIDENTS), f"incidents={len(INCIDENTS)} reports={len(REPORTS)} indicators={len(INDICATORS)} sources={len(SOURCES)}")
    print(len(INCIDENTS), "incidents,", len(REPORTS), "reports,", len(INDICATORS), "indicators,", len(SOURCES), "sources")


if __name__ == "__main__":
    main()
