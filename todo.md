# Lemtik Security — OSINT Methodology & Operations Manual
### Open-Source Intelligence Division
**Classification:** Internal Use Only
**Version:** 1.0
**Status:** Operational hello where are you guys I've been out this week ago Fish

---

## 1. What Lemtik OSINT Actually Is

Lemtik's OSINT product is a structured intelligence collection, analysis, and reporting service built specifically for the Lagos urban security environment. We monitor open and publicly available sources — social media, news, community channels, government statements, and digital signals — and convert raw information into actionable threat intelligence for our clients.

We are not a surveillance company. We do not monitor private communications, hack systems, or intercept protected data. Everything we collect is legally available in the public domain. Our value is not access — it is analysis. Anyone can scroll Twitter. Not everyone can turn Twitter into a threat brief that saves a client's life or assets.

**Our OSINT product answers three questions for every client:**
1. What is happening right now that could affect your security?
2. What patterns are emerging that you should prepare for?
3. What should you do about it this week?

---

## 2. Threat Profile — Lagos Urban Environment

Before monitoring anything, your team must understand what threats actually look like in Lagos. These are the threat categories Lemtik tracks for residential and corporate clients.

### 2.1 Physical Security Threats

**Kidnapping & Express Kidnapping**
- One-chance buses operating on specific routes
- Express kidnapping — ATM abductions, short-term ransom demands
- High-value individual targeting — executives, politicians, business owners
- Hotspot axes: Ajah, Badagry Expressway, Ikorodu Road, Third Mainland Bridge approaches

**Armed Robbery**
- Residential estate break-ins (usually intelligence-led — someone scoped the target)
- Bank and POS robberies
- Road robberies on specific corridors at specific times
- Patterns: usually spike before and after public holidays

**Area Boy Extortion & Civil Unrest**
- Construction site extortion
- Market levy enforcement
- Politically-motivated mobilisation (especially pre and post-election)
- Fuel subsidy, ASUU, or labour-related protest spillovers

**Cultism & Gang Activity**
- Territorial disputes between cult groups (Vikings, Eiye, Buccaneers, Black Axe)
- Recruitment activity near universities and polytechnics
- Revenge attacks following prior incidents

**Estate-Specific Threats**
- Insider threats — domestic staff, contractors with criminal connections
- Perimeter breaches — fence climbing, gate tailgating
- Vehicle theft patterns
- Fraud targeting estate residents (fake contractors, delivery scams)

### 2.2 Cyber & Digital Threats

**Business Email Compromise (BEC)**
- Fake vendor invoice scams targeting corporate finance teams
- CEO fraud — impersonating executives to authorise transfers
- Supply chain fraud — compromising vendor email accounts

**Social Engineering**
- SIM swap attacks targeting Nigerian bank customers
- Phishing targeting corporate email systems
- Fake recruitment scams targeting employees

**Reputational Threats**
- Coordinated social media attacks on brands or executives
- Misinformation campaigns
- Negative PR planted by competitors or disgruntled parties

### 2.3 Macro-Level Threats

**Political & Electoral**
- Pre-election tension and mobilisation
- Post-result protests and violence
- Thuggery and political violence, especially in LGA elections

**Economic Stress Signals**
- Naira devaluation impact on crime rates (historically correlated)
- Fuel scarcity and associated social tension
- Food price spikes and market unrest

**Public Health & Environmental**
- Flooding patterns affecting road access and evacuation routes
- Disease outbreak signals (cholera, Lassa fever)
- Industrial accidents near client locations

---

## 3. Source Architecture

Your monitoring is only as good as your sources. These are the sources Lemtik analysts monitor, organised by tier.

### Tier 1 — Primary Sources (Monitor Daily)

**Social Media**

| Platform | What to Monitor | Tools |
|---|---|---|
| Twitter/X | Keywords, hashtags, location tags, community accounts | TweetDeck, Twitonomy, Advanced Search |
| Facebook | Public community groups, neighbourhood pages, area pages | Manual monitoring, CrowdTangle (if accessible) |
| Telegram | Public channels — crime alerts, area news, political groups | Telegram Web, Telemetr.io |
| WhatsApp | Public broadcast channels (not private groups) | Manual |
| Instagram | Location tags, public accounts reporting incidents | Manual, Hashtag monitoring |

**Key Lagos Twitter/X Accounts to Monitor:**
- @LagosTraffic (LASTMA official)
- @LASG_LASEMA (LASEMA emergency)
- @PoliceNG_Force (Nigeria Police Force)
- @LagosStateGovt (Lagos State Government)
- Local journalists and crime reporters (build a list)
- Neighbourhood and community accounts (build a list per client location)

**Key Facebook Groups to Monitor (build a master list):**
- Lekki Residents Association
- VI Residents and Business Owners
- Ajah Community Watch
- Lagos Island Residents
- Ikoyi Residents Forum
- Any group relevant to client's specific location

**Key Telegram Channels to Monitor:**
- Lagos Crime Watch
- Nigeria Security Alert
- Area-specific community channels
- Political party channels during election periods

---

**News & Media**

| Source | Focus Area |
|---|---|
| Vanguard Nigeria | Crime, security, Lagos State news |
| The Punch | Crime, politics, business security |
| ThisDay | Corporate and business threats |
| Premium Times | Investigative, government, corruption |
| The Nation | General Lagos news |
| Channels TV online | Breaking news, civil unrest |
| Lagos State Government website | Official statements, policy |
| Nigeria Police Force website | Official crime reports |
| LASEMA Twitter/website | Emergency incidents |

**Google Alerts Setup:**
Create Google Alerts for the following terms and receive daily email digests:
- "Lagos robbery"
- "Lagos kidnapping"
- "Lagos shooting"
- "Lagos protest"
- "[Client's specific area] incident"
- "[Client company name]" (for corporate clients — reputational monitoring)
- "Lagos security"
- "Nigeria cybercrime"

---

**Government & Official Sources**

| Source | What it provides |
|---|---|
| Nigeria Police Force PRO statements | Official incident confirmations |
| LASEMA situation reports | Emergency and disaster incidents |
| Lagos State Ministry of Justice | Court cases, convictions |
| EFCC press releases | Financial crime arrests |
| DSS public statements | National security threats |
| FIRS / CBN advisories | Financial fraud warnings |

---

### Tier 2 — Secondary Sources (Monitor Weekly)

- Court filings and judgments (Nigeria Law Reports, CourtConnect)
- Company registration records (CAC — Corporate Affairs Commission)
- Land registry disputes (for property-related intelligence)
- Academic and research reports (CLEEN Foundation, SBM Intelligence, Nextier SPD)
- NGO security reports (International Crisis Group Nigeria, ACLED data)
- Insurance industry loss reports
- Interpol and FATF public notices

### Tier 3 — Human Intelligence Support (HUMINT-adjacent)

This is open-source adjacent — not surveillance, but structured relationship-building.

- Relationships with estate security managers who share incident information voluntarily
- Relationships with local journalists who share unpublished incident reports
- Relationships with community leaders and ward officers
- Formal partnerships with neighbourhood watch groups
- Client's own security staff as information sources (with permission)

**Important:** Lemtik never pays for information, never engages informants in the traditional intelligence sense, and never requests information that could compromise individuals or violate privacy laws. All HUMINT-adjacent activity is voluntary and relationship-based.

---

## 4. Monitoring Workflow

### 4.1 Daily Monitoring Routine

Every analyst follows this daily workflow:

**Morning Sweep (7:00am — 9:00am)**
- Check all Tier 1 social media sources for overnight incidents
- Review Google Alert digests
- Check LASEMA, Police PRO, and government social media
- Log all flagged items in the Lemtik Intelligence Log (see Section 6)
- Flag anything severity 4–5 for immediate client notification

**Midday Check (12:00pm — 1:00pm)**
- Quick scan of Twitter/X for breaking developments
- Check Telegram channels for new posts
- Update intelligence log with any new developments
- Follow up on any morning items that have developed further

**Evening Sweep (5:00pm — 7:00pm)**
- Full sweep of all sources
- Review any incidents that developed during the day
- Begin drafting any items for the weekly brief
- Flag weekend risk items for Friday brief inclusion

**Weekend**
- Reduced monitoring — one sweep Saturday morning, one Sunday evening
- Critical incidents (Severity 4–5) still trigger immediate alerts regardless of day

---

### 4.2 Keyword Monitoring Master List

Build and maintain this list. Update it monthly. Add client-specific keywords per engagement.

**Physical Security Keywords:**
- robbery, robbers, armed men, gunmen, shooting, shot, killed
- kidnap, kidnapping, abducted, missing, ransom
- one-chance, one chance, dangerous bus
- break-in, burglary, intruders, intruder
- area boys, agberos, cultists, cult, gang
- riot, protest, unrest, clash, violence, burning, looting
- bomb, explosion, blast, IED
- [specific client area name] + any of the above

**Cyber & Fraud Keywords:**
- fraud, scam, hacked, phishing, BEC, wire fraud
- SIM swap, account takeover, impersonation
- fake [client company name]
- investment scam, Ponzi, HYIP
- data breach, leaked, exposed

**Political & Macro Keywords:**
- protest, strike, shutdown, #EndSARS-style hashtags
- election violence, thugs, political thuggery
- fuel scarcity, fuel queue, stampede
- flood, flooding, displaced, evacuation

---

### 4.3 Incident Severity Classification

Every flagged item gets a severity rating before it enters the intelligence log.

| Level | Label | Description | Client Action |
|---|---|---|---|
| 1 | Informational | Background noise, no immediate threat | Weekly brief only |
| 2 | Low | Relevant pattern, low immediate risk | Weekly brief + trend note |
| 3 | Medium | Credible threat, elevated risk to client area | Weekly brief + highlighted callout |
| 4 | High | Active threat, direct relevance to client | Immediate alert + brief |
| 5 | Critical | Imminent danger to client or client's people | Immediate phone call + alert + brief |

**Severity 5 Response Protocol:**
1. Analyst immediately notifies Lemtik team lead
2. Team lead verifies information from at least two sources
3. Client security manager contacted by phone within 15 minutes
4. Written alert sent via WhatsApp and email within 30 minutes
5. Situation monitored continuously until resolved
6. Full incident report delivered within 24 hours

---

## 5. Intelligence Products

Lemtik delivers intelligence in three formats

### 5.1 Weekly Intelligence Brief

**Delivery:** Every Monday by 8:00am
**Format:** Branded PDF (3–6 pages)
**Audience:** Security manager and senior management

**Structure:**

---
**Page 1 — Executive Summary**
- Week's risk rating (Red / Orange / Green)
- 3–5 bullet points of the most important intelligence items
- One key recommendation for the week

**Page 2 — Threat Landscape**
- Physical security threats relevant to client's area this week
- Specific incidents that occurred nearby (with source citations)
- Emerging patterns or trends to watch

**Page 3 — Digital & Fraud Threats**
- Cyber threats relevant to client's sector
- Fraud patterns targeting similar organisations
- Social engineering alerts

**Page 4 — OSINT Signals**
- Specific social media posts or channels flagged this week (screenshots if relevant)
- Community intelligence — what are residents and locals saying?
- Political and macro developments that could affect security posture

**Page 5 — Recommendations**
- 2–3 specific, actionable recommendations based on this week's intelligence
- Any changes recommended to security posture, patrol routes, or access protocols

**Page 6 — Appendix**
- Full source list for the week
- Raw intelligence log summary
- Glossary of terms (for non-security clients)

---

### 5.2 Immediate Threat Alert

**Delivery:** WhatsApp + Email, within 30 minutes of verification
**Format:** Short text message (WhatsApp) + 1-page PDF (Email)
**Trigger:** Severity 4 or 5 incidents only

**WhatsApp Alert Format:**
```
🔴 LEMTIK SECURITY ALERT — [DATE] [TIME]

THREAT: [One sentence description]
LOCATION: [Specific area]
SEVERITY: HIGH / CRITICAL
SOURCE: [e.g., Multiple social media reports + police scanner]

RECOMMENDED ACTION: [One specific action]

Full report to follow within 30 minutes.
— Lemtik Security Intelligence
```

**1-Page PDF Alert includes:**
- Incident description
- Source verification summary
- Map showing incident location relative to client
- Immediate recommended actions
- Lemtik analyst contact for questions

---

### 5.3 Monthly Threat Analysis Report

**Delivery:** First Monday of every month
**Format:** Branded PDF (8–12 pages)
**Audience:** Security manager + C-suite / board

**Structure:**
- Month in review — key incidents and how client's security held up
- Trend analysis — what changed from last month?
- Hotspot mapping — where did incidents cluster?
- Sector comparison — how does client's area compare to wider Lagos?
- 90-day outlook — what should client prepare for in the coming quarter?
- Strategic recommendations — longer-term security posture adjustments

**This report justifies the contract renewal every month.**

---

## 6. Intelligence Logging System

Until the Lemtik platform is built, use this structure in Notion, Airtable, or Google Sheets.

### Intelligence Log Fields

| Field | Description |
|---|---|
| Log ID | Auto-generated (LEM-OSINT-001, LEM-OSINT-002...) |
| Date/Time Collected | When analyst found it |
| Source | Exact source (Twitter account, Facebook group, news outlet) |
| Source URL | Direct link to original post or article |
| Raw Content | Exact text or screenshot of the original post |
| Summary | Analyst's one-sentence summary |
| Threat Category | Physical / Cyber / Political / Macro |
| Severity | 1–5 |
| Location Relevance | Which client(s) or areas does this affect? |
| Verified | Yes / No / Partial |
| Verification Source | Second source confirming the information |
| Client Notified | Yes / No |
| Notification Method | Alert / Brief / Phone |
| Status | Active / Monitoring / Resolved / Archived |
| Analyst | Who logged it |
| Notes | Any additional context |

---

## 7. Source Verification Protocol

**The single most important rule in OSINT: never report unverified information to a client.**

A false alert damages trust permanently. A missed threat is bad. A false threat that causes a client to make the wrong decision is worse.

### Verification Standards by Severity

**Severity 1–2:** Single credible source sufficient. Note that it is unverified.

**Severity 3:** Two independent sources required, or one primary source (official account, major news outlet).

**Severity 4:** Two independent sources required. At minimum one must be a credible institutional source (police, news, LASEMA). Cross-reference with community sources.

**Severity 5:** Two independent credible sources required before client notification. If only one source exists but threat is imminent, notify client with explicit caveat: "Unconfirmed but credible single-source report. Taking precautionary action."

### Source Credibility Hierarchy

**Tier A — Highest credibility:**
- Official government accounts (verified)
- Major Nigerian news outlets (Vanguard, Punch, Channels)
- Police Force official statements
- LASEMA official reports

**Tier B — Credible but verify:**
- Established community pages with track record
- Local journalists with known credibility
- Multiple independent community reports of same incident

**Tier C — Use with caution:**
- Anonymous social media posts
- Unverified community reports
- Single-source WhatsApp forwards
- Accounts with no history

**Never use as sole source:**
- Anonymous Telegram posts
- Unverified viral content
- Accounts created recently with no history
- Information that cannot be cross-referenced

---

## 8. Legal & Ethical Framework

Lemtik operates within clear legal and ethical boundaries. Every analyst must understand and follow these rules.

### What We Do

- Monitor publicly available information only
- Collect information that any member of the public could access
- Analyse and synthesise information to produce intelligence
- Report findings to authorised clients for legitimate security purposes

### What We Never Do

- Access private communications without consent
- Hack, infiltrate, or gain unauthorised access to any system
- Pay sources for information
- Monitor specific private individuals without their consent
- Share client intelligence with third parties without explicit permission
- Collect information on a person's political views, religion, or ethnicity for profiling purposes
- Violate Nigeria's Cybercrimes Act 2015 or any applicable data protection regulation
- Violate Nigeria Data Protection Act (NDPA) 2023

### Data Handling Rules

- All intelligence logs stored securely with access limited to authorised analysts
- Client reports encrypted in transit and at rest
- No client data shared between clients under any circumstances
- Raw intelligence logs retained for 12 months then archived or deleted
- Analysts sign a confidentiality agreement before accessing any client data

### When to Refuse a Client Request

Lemtik will refuse to conduct OSINT operations that involve:
- Monitoring a private individual without lawful basis
- Competitive intelligence that crosses into industrial espionage
- Political opposition research
- Monitoring of journalists, activists, or civil society organisations
- Any request that appears designed to facilitate harm to a specific person

If a client makes such a request, escalate to Lemtik leadership immediately. Do not attempt to fulfil or negotiate the request.

---

## 9. Pricing Structure

### OSINT Service Tiers

**Tier 1 — Basic Intelligence Brief**
- Weekly intelligence brief (Monday delivery)
- Covers client's immediate geographic area
- Physical security threats only
- ₦100,000/month

**Tier 2 — Standard Intelligence Package**
- Weekly intelligence brief
- Monthly threat analysis report
- Severity 4–5 immediate alerts
- Physical + cyber threat monitoring
- Client-specific keyword monitoring
- ₦200,000/month

**Tier 3 — Premium Intelligence Package**
- Everything in Standard
- 24/7 monitoring (with on-call analyst)
- Daily morning situation report (short format)
- Executive threat briefing (verbal, monthly)
- Customised source development for client's specific environment
- Competitor and reputational monitoring
- ₦400,000/month

**Add-On Services:**

| Service | Price |
|---|---|
| One-time security threat assessment | ₦350,000 |
| Executive travel security brief (per trip) | ₦75,000 |
| Event security intelligence brief | ₦150,000 |
| Incident-specific deep dive investigation | ₦200,000 |
| Staff background verification (OSINT-based) | ₦25,000 per person |

### Revenue Targets

| Milestone | Clients | Monthly Revenue |
|---|---|---|
| Break-even | 3 x Standard | ₦600,000/month |
| Sustainable | 5 x Standard + 1 x Premium | ₦1,400,000/month |
| Growth stage | 5 Standard + 3 Premium + add-ons | ₦2,200,000+/month |

---

## 10. Analyst Skills & Team Structure

### MVP Team (What You Need Right Now)

**Lead Analyst (1 person — can be founder initially)**
- Oversees all intelligence production
- Client relationship management
- Final sign-off on all briefs before delivery
- Develops and maintains source network
- Skills needed: research, writing, analytical thinking, Lagos security knowledge

**Junior Analyst (1–2 people from your tech team initially)**
- Daily monitoring and log entry
- First draft of weekly briefs
- Social media monitoring
- Skills needed: attention to detail, research skills, good written English, discretion

**As you grow, add:**
- Cyber intelligence specialist (for Tier 3 clients)
- Regional analysts (when you expand beyond Lagos)
- Graphic designer (for report design and branding)

### Analyst Training Requirements

Every analyst must complete before working on client accounts:
1. Read and sign Lemtik Ethics and Legal Framework
2. Complete basic OSINT training (free resources: OSINT Framework, Bellingcat guides, TraceLabs methodology)
3. Complete Lagos security environment briefing (internal document)
4. Shadow senior analyst for 2 weeks before independent work
5. First 3 solo briefs reviewed and approved by lead analyst

**Free OSINT Training Resources:**
- osintframework.com — comprehensive tool directory
- bellingcat.com/resources — practical OSINT guides
- start.me/p/rx9Gjj/osint-tools — curated tool collection
- Intel Techniques by Michael Bazzell (book + podcast)
- Trace Labs OSINT for Good (practical exercises)

---

## 11. Client Onboarding Process

When a new OSINT client signs, follow this onboarding sequence.

**Week 1 — Intelligence Intake**
Conduct a 60-minute intake session with client's security manager covering:
- What are your biggest current security concerns?
- What incidents have you experienced in the last 12 months?
- Who are your key people we should monitor for executive threats?
- What geographic area do you need us to cover?
- What are your competitor or reputational concerns? (for corporate clients)
- Who receives our reports and alerts?
- What is the preferred format — WhatsApp, email, PDF, verbal briefing?
- Are there any topics or areas we should avoid for legal or sensitivity reasons?

**Week 1 — Environment Assessment**
- Analyst conducts desktop survey of client's location using Google Maps, Street View
- Reviews any publicly available incident history for the area
- Identifies key community groups, social media accounts, and sources specific to client's area
- Builds client-specific keyword list

**Week 2 — Shadow Brief**
Produce first brief internally without delivering to client. Review for accuracy, format, and relevance. Adjust methodology based on what you find.

**Week 3 — First Delivery**
Deliver first weekly brief. Follow up with a 30-minute call to get feedback. Adjust format, depth, and focus based on client response.

**Month 1 Review**
At the end of the first month, conduct a formal review call:
- Is the brief format working for them?
- Are we covering the right threats?
- Are alerts reaching the right people?
- Any gaps in coverage?
- Upsell opportunity assessment

---

## 12. Tools & Technology Stack

### Free Tools for MVP Stage

**Social Media Monitoring:**
- TweetDeck — multi-column Twitter monitoring
- Google Alerts — keyword monitoring across news and web
- Telegram Web — channel monitoring
- Facebook Pages — manual group monitoring

**Research & Investigation:**
- Google Dorking — advanced search operators for finding hidden information
- Wayback Machine (web.archive.org) — historical website snapshots
- Pipl / Spokeo — person search (limited free use)
- Shodan — internet-connected device search (cybersecurity)
- WHOIS lookup — domain registration information

**Mapping & Geolocation:**
- Google Maps — location verification
- Google Earth — satellite imagery
- What3Words — precise location referencing (used by Nigeria emergency services)

**Document & Report Production:**
- Canva — branded PDF report design (free tier sufficient)
- Google Docs — collaborative brief drafting
- Notion or Airtable — intelligence logging database

**Communication:**
- WhatsApp Business — client alerts
- Gmail — email delivery
- Calendly — scheduling client calls



## The Three Scaling Phases

```
Phase 1 — Stabilise (Now → Month 3)
  Fix the current codebase. More sources. Better filtering.
  Scheduled auto-collection. First paying client.

Phase 2 — Productise (Month 3 → Month 9)
 API layer.
  Real-time alerts. NLP classification. PostgreSQL migration.

Phase 3 — Industrialise (Month 9 → Month 24)
  Kafka pipeline. Elasticsearch. AI threat scoring.
  Dark web monitoring. Pan-Nigeria expansion.
  Government-grade platform.
```

---

## Phase 1 — Stabilise the Current Codebase

### 1.1 Fix False Positives (Week 1 — Critical)

Your current keyword matching is substring-based. "bec" matches "biscuits."
"strike" matches "airstrikes." This produces garbage intelligence.
Replace every keyword check with whole-word regex matching.

```python
import re

def keyword_matches(text: str, keywords: list[str]) -> list[str]:
    lower = text.lower()
    hits = []
    for kw in keywords:
        # Escape special chars, match whole words only
        pattern = r'(?<!\w)' + re.escape(kw) + r'(?!\w)'
        if re.search(pattern, lower):
            hits.append(kw)
    return hits
```

Impact: eliminates ~60% of current false positives immediately.

---

### 1.2 Geographic Relevance Filter (Week 1 — Critical)

Stories about Gaza, Iran, Ebonyi, and Sambisa are not Lagos intelligence.
Add a two-tier geographic filter before any item enters your database.

```python
NIGERIA_KEYWORDS = [
    "nigeria", "nigerian", "abuja", "lagos", "kano", "ibadan",
    "port harcourt", "enugu", "kaduna", "benin city", "onitsha",
    "aba", "warri", "zaria", "ilorin", "jos", "maiduguri",
    "efcc", "dss", "nsc", "npf", "police nigeria",
    "lasema", "lastma", "lawma",
]

LAGOS_KEYWORDS = [
    "lagos", "lekki", "victoria island", "vi", "ikoyi", "ajah",
    "ikeja", "surulere", "yaba", "oshodi", "alaba", "festac",
    "badagry", "ikorodu", "epe", "agege", "mushin", "isale eko",
    "apapa", "tin can", "maryland", "ojota", "mile 2",
    "sangotedo", "jakande", "chevron", "osapa", "igbo efon",
]

def geo_relevance_score(text: str, custom_keywords: list[str]) -> str:
    """Returns 'Lagos', 'Nigeria', 'None' """
    lower = text.lower()
    if any(kw in lower for kw in LAGOS_KEYWORDS + custom_keywords):
        return "Lagos"
    if any(kw in lower for kw in NIGERIA_KEYWORDS):
        return "Nigeria"
    return "None"
```

Items with geo_relevance = "None" are skipped entirely unless a
client-specific keyword matches. This alone makes your briefs
immediately more credible.

---

### 1.3 Scheduled Auto-Collection (Week 2)

Stop requiring someone to click "Collect." Use APScheduler to run
collection automatically every 6 hours, 24/7.

```bash
pip install apscheduler
```

```python
# In your app startup
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler(timezone="Africa/Lagos")

scheduler.add_job(
    collect_all_sources,
    'cron',
    hour='6,12,18,0',   # 6am, 12pm, 6pm, midnight Lagos time
    id='auto_collect',
    replace_existing=True
)

scheduler.add_job(
    generate_and_email_weekly_brief,
    'cron',
    day_of_week='mon',
    hour=7,
    minute=0,
    id='weekly_brief',
    replace_existing=True
)

scheduler.start()
```

---

### 1.4 Fix SSL Error for NPF and Government Sites (Week 2)

Nigerian government websites often have certificate issues.
Create a lenient context only for known-problematic domains.

```python
import ssl

LENIENT_SSL_DOMAINS = [
    "npf.gov.ng", "lagosstate.gov.ng", "efccnigeria.org",
    "lasema.gov.ng", "lasg.gov.ng",
]

def fetch_public_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    use_lenient = any(domain in parsed.netloc for domain in LENIENT_SSL_DOMAINS)

    ctx = ssl.create_default_context()
    if use_lenient:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "LemtikSecurityOSINT/1.0 (public-source analyst tool)",
            "Accept": "text/html,application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
        return response.read(1_000_000).decode("utf-8", errors="replace")
```

---

### 1.5 Expand Source Coverage (Week 2)

Add these RSS feeds to your DEFAULT_SOURCES immediately.
All are free, all are high-credibility Nigerian sources.

```python
EXPANDED_SOURCES = [
    # Tier A — Nigerian News
    ("Premium Times",     "News",     "https://www.premiumtimesng.com/feed",          "A"),
    ("The Nation",        "News",     "https://thenationonlineng.net/feed/",           "A"),
    ("Daily Trust",       "News",     "https://dailytrust.com/feed",                   "A"),
    ("Guardian Nigeria",  "News",     "https://guardian.ng/feed/",                     "A"),
    ("Thisday Live",      "News",     "https://www.thisdaylive.com/index.php/feed/",   "A"),

    # Tier A — Official
    ("EFCC Nigeria",      "Official", "https://efccnigeria.org/efcc/feed",             "A"),
    ("CBN Nigeria",       "Official", "https://www.cbn.gov.ng/rss/",                  "A"),

    # Tier B — Investigative
    ("SaharaReporters",   "News",     "https://saharareporters.com/rss.xml",           "B"),
    ("Peoples Gazette",   "News",     "https://gazettengr.com/feed/",                  "B"),
    ("HumAngle",          "News",     "https://humanglemedia.com/feed/",               "B"),

    # Tier B — Twitter via Nitter RSS (no API key needed)
    ("NigeriaPolice@X",  "Social",   "https://nitter.net/PoliceNG_Force/rss",         "B"),
    ("LASEMA@X",         "Social",   "https://nitter.net/LASG_LASEMA/rss",            "B"),
    ("LagosTraffic@X",   "Social",   "https://nitter.net/LagosTraffic/rss",           "B"),
    ("ChannelsTV@X",     "Social",   "https://nitter.net/channelstv/rss",             "B"),
]
```

**Why Nitter:** Twitter/X blocks direct scraping. Nitter is an open-source
frontend that exposes RSS feeds for any public Twitter account.
No API key, no cost. Use `nitter.net` or self-host a Nitter instance
for reliability.

---

### 1.6 Phase 1 Target State

By end of Month 3 your pipeline should:

| Metric | Current | Target |
|---|---|---|
| Sources monitored | 7 | 20+ |
| False positive rate | ~40% | <10% |
| Collection frequency | Manual | Every 6 hours |
| Geographic filtering | None | Lagos + Nigeria tiers |
| SSL failures | 1+ | 0 |
| Weekly briefs | Manual | Auto-generated + emailed |
| Paying clients | 0 | 1–2 |

---

## Phase 2 — Productise (Month 3 → Month 9)

This phase converts your single-tenant Python script into a proper
multi-tenant SaaS platform. This is the architecture shift that
allows you to serve 50 clients simultaneously.

### 2.1 Migrate from SQLite to PostgreSQL

SQLite works for one user on one machine. The moment you have
multiple clients, concurrent writes, or deploy to a server,
you need PostgreSQL.

**Migration path:**
- Provision a Supabase project (free tier)
- Use Alembic (Python migration tool) to recreate your schema in Postgres
- Update all `sqlite3` calls to use `psycopg2` or SQLAlchemy
- Add `org_id` foreign key to every table for multi-tenancy

```bash
pip install psycopg2-binary sqlalchemy alembic
```

**Multi-tenancy schema addition:**
Every table gets an `org_id` column. Every query filters by `org_id`.
Client A never sees Client B's data. This is the foundation of SaaS.

```sql
-- Add to every table
org_id UUID NOT NULL REFERENCES organisations(id),

-- Every query becomes
SELECT * FROM incidents
WHERE org_id = $1
AND collected_at >= $2
ORDER BY severity DESC;
```

---

### 2.2 Build the API Layer (FastAPI)

Replace your current Flask/web UI with a proper REST API.
This separates the backend from the frontend and allows you to
build a proper React dashboard later.

**Why FastAPI over Flask:**
- Automatic OpenAPI documentation (your clients can see your API)
- Native async support — critical for concurrent collection jobs
- Type safety via Pydantic — catches bugs before runtime
- 3x faster than Flask for I/O-heavy workloads

```bash
pip install fastapi uvicorn pydantic python-jose passlib
```


---

### 2.3 Add NLP Classification (The Intelligence Upgrade)

This is the biggest upgrade in Phase 2. Instead of keyword matching,
you use a proper NLP model to classify threats. The difference:

- **Keyword matching:** "strike" matches "airstrikes" (wrong)
- **NLP classification:** understands context, extracts entities,
  determines actual threat relevance

**Tools — free and open source:**

```bash
pip install spacy transformers torch
python -m spacy download en_core_web_sm
```

**Named Entity Recognition (NER) — extract locations, organisations, people:**

```python
import spacy

nlp = spacy.load("en_core_web_sm")

def extract_entities(text: str) -> dict:
    doc = nlp(text)
    return {
        "locations": [ent.text for ent in doc.ents if ent.label_ in ("GPE", "LOC")],
        "organisations": [ent.text for ent in doc.ents if ent.label_ == "ORG"],
        "people": [ent.text for ent in doc.ents if ent.label_ == "PERSON"],
    }

# Usage
entities = extract_entities("Police arrested three suspects in Lekki Phase 1 after a robbery")
# Returns: {"locations": ["Lekki Phase 1"], "organisations": ["Police"], "people": []}
```

**Sentiment and Threat Scoring — use a pre-trained model:**

```python
from transformers import pipeline

# Load once at startup — do not load per request
threat_classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased-finetuned-sst-2-english",
    device=-1  # CPU (use 0 for GPU if available)
)

def classify_threat_sentiment(text: str) -> float:
    """Returns a 0.0–1.0 threat score"""
    result = threat_classifier(text[:512])[0]
    if result["label"] == "NEGATIVE":
        return round(result["score"], 3)
    return round(1.0 - result["score"], 3)
```

**Fine-tuning for Lagos (Month 6+):**
As you accumulate verified incidents, you build a labelled dataset
and fine-tune a model specifically on Nigerian security language.
"Agberos," "one-chance," "area boys" — these terms mean nothing
to a US-trained model. Your fine-tuned model will outperform
Recorded Future on Nigerian threat intelligence.
This is your long-term technical moat.

---

### 2.4 Real-Time Alert Pipeline

When a Severity 4–5 incident is detected, clients must know
within minutes, not the next morning's brief.

**Architecture:**

```
Collection job detects Severity 4+
    ↓
Publish to Redis Pub/Sub channel
    ↓
Alert worker picks up event
    ↓
Parallel dispatch:
    ├── WhatsApp (Twilio) → client security manager
    ├── SMS (Termii) → backup number
    └── Email (Resend) → full alert PDF
```

```python
# requirements
pip install redis twilio resend

# Alert dispatcher
import redis
import json

redis_client = redis.from_url(os.getenv("REDIS_URL"))

def publish_alert(incident: dict) -> None:
    if incident["severity"] >= 4:
        redis_client.publish(
            "lemtik:alerts",
            json.dumps({
                "incident_id": incident["log_id"],
                "severity": incident["severity"],
                "summary": incident["summary"],
                "org_ids": get_affected_orgs(incident),
            })
        )

# Alert worker (runs as separate process)
def alert_worker():
    pubsub = redis_client.pubsub()
    pubsub.subscribe("lemtik:alerts")
    for message in pubsub.listen():
        if message["type"] == "message":
            alert = json.loads(message["data"])
            dispatch_whatsapp(alert)
            dispatch_sms(alert)
            dispatch_email(alert)
```

---

---


---

## Phase 3 — Industrialise (Month 9 → Month 24)

This is where Lemtik becomes infrastructure, not just a service.
The architecture at this phase is what enterprise and government
clients require.

### 3.1 Event Streaming with Apache Kafka

At scale, your collection pipeline produces thousands of items per hour
across dozens of sources. A synchronous Python loop cannot handle this.
You need an event streaming architecture.

**What Kafka does:**
Every collected item is published as an event. Multiple independent
workers consume events in parallel — one for NLP classification,
one for geo-filtering, one for alert detection, one for storage.
Each worker can be scaled independently.

```
Sources (RSS, scraper, social)
    ↓
Kafka Topic: raw_intelligence
    ↓
Consumer Group 1: NLP Classifier → Topic: classified_intelligence
Consumer Group 2: Geo Filter → Topic: filtered_intelligence
Consumer Group 3: Deduplicator → Topic: unique_intelligence
Consumer Group 4: Alert Detector → Topic: alerts
    ↓
Storage Workers → PostgreSQL + Elasticsearch
Alert Workers → WhatsApp + SMS + Email
```

**Setup with Docker Compose (development):**

```yaml
version: '3.8'
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    depends_on: [zookeeper]
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: 'true'
```

```bash
pip install kafka-python confluent-kafka
```

**Production hosting:** Confluent Cloud free tier (no server management)
or Upstash Kafka (serverless, pay per message).

---

### 3.2 Elasticsearch for Intelligence Search

At 10,000+ incidents, PostgreSQL LIKE queries become slow.
Elasticsearch provides:
- Full-text search across all intelligence in milliseconds
- Fuzzy matching ("leki" finds "Lekki")
- Aggregations for heatmaps and trend analysis
- Near-real-time indexing

```bash
pip install elasticsearch
```

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(os.getenv("ELASTICSEARCH_URL"))

# Index incident
es.index(
    index="lemtik_incidents",
    id=incident["log_id"],
    document={
        "summary": incident["summary"],
        "category": incident["threat_category"],
        "severity": incident["severity"],
        "location": incident["location_relevance"],
        "collected_at": incident["collected_at"],
        "geo_point": {
            "lat": incident.get("lat"),
            "lon": incident.get("lng"),
        }
    }
)

# Search
results = es.search(
    index="lemtik_incidents",
    query={
        "bool": {
            "must": [{"match": {"summary": "kidnapping"}}],
            "filter": [
                {"term": {"category": "Physical"}},
                {"range": {"severity": {"gte": 3}}}
            ]
        }
    }
)
```

**Hosting:** Elastic Cloud free trial, then $16/month.
Or self-host on a $6/month DigitalOcean droplet.

---

### 3.3 AI Threat Intelligence Layer

This is what separates Lemtik from every other Lagos security firm.
By Phase 3 you have 6–12 months of verified Nigerian threat data.
You use it to build models that no external vendor can replicate.

**Model 1 — Lagos Threat Classifier**
Fine-tuned on your own verified incident dataset.
Classifies incidents with far higher accuracy than generic NLP models.
Understands Nigerian pidgin, local place names, local criminal vocabulary.

```python
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)

# Fine-tune on your verified incidents
# Your verified incidents become training data
# Labels: Physical / Cyber / Political / Macro / Irrelevant
```

**Model 2 — Predictive Risk Scoring**
Uses historical incident patterns to predict:
- Which areas will have elevated risk this weekend?
- Does a spike in political activity correlate with robbery increases?
- What is the 7-day risk forecast for a client's location?

Tools: scikit-learn for baseline models, Prophet for time-series forecasting.

```bash
pip install scikit-learn prophet
```

**Model 3 — Entity Network Mapping**
Links people, locations, organisations across incidents.
"Is this the same gang that robbed three estates in Lekki last month?"
Tool: NetworkX for graph analysis, Neo4j for production.

---

### 3.4 Dark Web Monitoring (Government-Grade Feature)

Criminal networks in Nigeria increasingly use Telegram private channels,
dark web forums, and encrypted messaging to coordinate.

**What this monitors:**
- Tor hidden services (.onion sites) mentioning Nigerian targets
- Paste sites (Pastebin, Ghostbin) with leaked Nigerian data
- Criminal Telegram channels (public ones you can join)
- Data breach marketplaces for leaked Nigerian credentials

**Tools:**
```bash
pip install stem requests[socks]  # Tor access
pip install telethon               # Telegram monitoring
```

**Important:** Dark web monitoring requires a dedicated secure environment
(separate VM, VPN, Tor), strict legal framework, and eventually a
security clearance arrangement with appropriate government bodies.
Do not build this until you have a legal team review.

---

### 3.5 Multi-Region Expansion Architecture

Lagos → Nigeria → West Africa.

When you expand beyond Lagos, your architecture must support:
- Per-city intelligence teams and source sets
- City-specific NLP models (Abuja threats ≠ Lagos threats)
- Cross-city pattern detection (kidnapping gang moving from Abuja to Lagos)
- Country-specific client isolation (Nigerian client cannot see Ghanaian data)

**Database partitioning strategy:**
```sql
-- Partition incidents by region for query performance
CREATE TABLE incidents_lagos PARTITION OF incidents
    FOR VALUES IN ('lagos');

CREATE TABLE incidents_abuja PARTITION OF incidents
    FOR VALUES IN ('abuja');

CREATE TABLE incidents_portHarcourt PARTITION OF incidents
    FOR VALUES IN ('port_harcourt');
```

---

### 3.6 Government-Grade Security Requirements

When you pitch Lagos State Government, they will ask about these.
Build them before the pitch, not after.

**ISO 27001 alignment** (not certification yet, but alignment):
- Asset inventory
- Access control policy
- Incident response procedure
- Data classification policy
- Business continuity plan

**Data residency:**
All Nigerian data must stay in Nigeria or at minimum Africa.
Use AWS Africa (Cape Town) or Azure South Africa North region.
Do not store government client data on US servers.

**Audit logging:**
Every query, every export, every login logged immutably.
Government clients will ask "who saw this data and when?"

**Penetration testing:**
Before any government contract, commission a pentest.
Several Nigerian cybersecurity firms offer this.
Budget ₦500,000–₦1,500,000.

---

## Full Technology Stack by Phase

### Phase 1 — Current + Fixes
```
Language:       Python 3.11+
Web framework:  Flask (keep for now)
Database:       SQLite → migrate in Phase 2
Scheduling:     APScheduler
NLP:            Regex keyword matching → upgrade Phase 2
Scraping:       urllib + feedparser
Hosting:        Local / PythonAnywhere free tier
Cost:           ₦0/month
```

### Phase 2 — Productise
```
Language:       Python (backend) 
API:            FastAPI + Uvicorn
Database:       PostgreSQL (Supabase)
Cache/Queue:    Redis (Upstash)
NLP:            spaCy + HuggingFace Transformers
Search:         PostgreSQL full-text (upgrade to ES in Phase 3)
Alerts:         Redis Pub/Sub + Twilio + Termii + Resend
Scheduling:     APScheduler → Celery (when jobs exceed 10)
Hosting:        Railway (API) + Vercel (frontend) + Supabase (DB)
Cost:           ~$50/month (~₦75,000/month)
Revenue needed: 1 client at ₦150,000 covers it
```

### Phase 3 — Industrialise
```
Language:       Python + TypeScript + Go (high-performance scrapers)
API:            FastAPI (microservices)
Database:       PostgreSQL (Supabase Pro) + Elasticsearch
Streaming:      Apache Kafka (Confluent Cloud)
Cache:          Redis Cluster
NLP:            Fine-tuned Nigerian threat model (HuggingFace)
ML:             scikit-learn + Prophet (forecasting) + PyTorch (custom models)
Graph:          Neo4j (entity network mapping)
Monitoring:     Prometheus + Grafana
Hosting:        AWS Africa (Cape Town) — data residency compliance
CI/CD:          GitHub Actions + Docker + Kubernetes
Cost:           ~$500–$1,500/month
Revenue needed: 5+ enterprise clients
```

---

## Data Pipeline Architecture (Phase 3 Full View)

```
┌─────────────────────────────────────────────────────────────────┐
│                     COLLECTION LAYER                            │
│  RSS Scrapers │ Twitter/Nitter │ Telegram │ Web Crawlers │ HUMINT│
└──────────────────────────┬──────────────────────────────────────┘
                           │ raw events
┌──────────────────────────▼──────────────────────────────────────┐
│                   KAFKA EVENT BUS                               │
│   Topic: raw_intelligence (all collected items)                 │
│   Topic: classified (after NLP)                                 │
│   Topic: alerts (severity 4+)                                   │
└──────────┬─────────────────────────────┬───────────────────────┘
           │                             │
┌──────────▼──────────┐     ┌────────────▼────────────────────────┐
│  NLP PROCESSING     │     │      ALERT DISPATCHER               │
│  - Entity extraction│     │  - WhatsApp (Twilio)                │
│  - Threat scoring   │     │  - SMS (Termii)                     │
│  - Geo classification│    │  - Email (Resend)                   │
│  - Deduplication    │     │  - In-app (WebSocket)               │
└──────────┬──────────┘     └─────────────────────────────────────┘
           │ enriched events
┌──────────▼──────────────────────────────────────────────────────┐
│                     STORAGE LAYER                               │
│   PostgreSQL (structured data, multi-tenant, per-client)        │
│   Elasticsearch (full-text search, aggregations, heatmaps)      │
│   S3/Cloudinary (evidence files, report PDFs)                   │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────┐
│                   INTELLIGENCE LAYER                            │
│   Threat scoring models │ Predictive analytics │ Network graphs  │
│   Weekly brief generator │ Monthly report engine                 │
└──────────┬──────────────────────────────────────────────────────┘
        

### Tools to Add as Revenue Grows

| Tool | Purpose | Cost |
|---|---|---|
| Maltego | Link analysis and relationship mapping | $999/year |
| Recorded Future | Automated threat intelligence | Enterprise pricing |
| Babel Street | Social media monitoring at scale | Enterprise pricing |
| i2 Analyst's Notebook | Intelligence visualization | Enterprise pricing |
| Brandwatch | Social media monitoring | $1,000+/month |

**You do not need any paid tools at MVP stage.** Free tools plus analyst skill is sufficient for your first 10 clients.

---

## 13. First 30 Days — Action Plan

**Week 1**
- Set up intelligence logging system in Notion or Airtable
- Create Google Alerts for 20 core Lagos security keywords
- Build master list of Twitter accounts, Facebook groups, and Telegram channels to monitor
- Set up TweetDeck with monitoring columns
- Complete Bellingcat OSINT beginner guide (free, online)
- Draft Lemtik OSINT brief template in Canva

**Week 2**
- Begin daily monitoring routine
- Produce one full mock brief (pick a real Lagos estate as a fictional client)
- Review mock brief internally — is it accurate? Useful? Well-written?
- Refine template based on review
- Identify 10 potential clients (estate managers, corporate security heads) to approach

**Week 3**
- Approach 5 potential clients with a free sample brief
- The brief is for their actual location — this demonstrates value immediately
- Collect feedback from anyone willing to give it
- Refine product based on feedback

**Week 4**
- Convert at least one free sample recipient to a paying client
- Formalise client onboarding process
- Set up WhatsApp Business account for client alerts
- Produce first official paid brief

**Target by end of Month 1:** One paying client at ₦150,000–₦200,000/month.

---

*Document version 1.0 — Lemtik Security Internal Use Only*
*This document is the operational foundation of Lemtik's intelligence division.*
*Update quarterly as sources, tools, and threat landscape evolve.*