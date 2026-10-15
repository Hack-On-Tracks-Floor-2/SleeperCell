from enum import Enum
from typing import Dict, Optional, Literal
from pydantic import BaseModel, Field
from genai.llm_client import get_llm_client, wrap_untrusted
from pipeline.db import get_connection
from datetime import datetime, timezone

class DestinationCategory(str, Enum):
    CLOUD_STORAGE = "cloud_storage"
    PERSONAL_WEBMAIL = "personal_webmail"
    PASTE_SITE = "paste_site"
    MESSAGING = "messaging"
    DEV_TOOL = "dev_tool"
    BUSINESS_SAAS = "business_saas"
    UNKNOWN = "unknown"

class DestinationClassification(BaseModel):
    category: DestinationCategory
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: Optional[str] = None

DEST_CLASSIFIER_PROMPT = """You are a cybersecurity destination classification model for an insider threat detection platform.
Your task is to classify an external internet domain name into exactly one of these categories:
- cloud_storage (e.g. dropbox.com, megashare-demo.net, drive.google.com, box.com)
- personal_webmail (e.g. mail.yahoo.com, protonmail.com, mail.google.com)
- paste_site (e.g. pastebin.com, ghostbin.co, controlc.com)
- messaging (e.g. slack.com, discord.com, telegram.org, whatsapp.com)
- dev_tool (e.g. github.com, gitlab.com, pypi.org, registry.npmjs.org)
- business_saas (e.g. salesforce.com, netsuite.com, workday.com, bloomberg.com, hubspot.com)
- unknown (e.g. obscure or unverified domains)

Return strictly a valid JSON object matching the DestinationClassification schema.
"""

# Static dictionary for instantaneous resolution of common domains
STATIC_RULES: Dict[str, Tuple_Category_Confidence := tuple] = {
    "dropbox.com": (DestinationCategory.CLOUD_STORAGE, 0.99),
    "megashare-demo.net": (DestinationCategory.CLOUD_STORAGE, 0.95),
    "drive.google.com": (DestinationCategory.CLOUD_STORAGE, 0.99),
    "pastebin.com": (DestinationCategory.PASTE_SITE, 0.99),
    "protonmail.com": (DestinationCategory.PERSONAL_WEBMAIL, 0.99),
    "slack.com": (DestinationCategory.MESSAGING, 0.99),
    "github.com": (DestinationCategory.DEV_TOOL, 0.99),
    "pypi.org": (DestinationCategory.DEV_TOOL, 0.99),
    "salesforce.com": (DestinationCategory.BUSINESS_SAAS, 0.99),
    "workday.com": (DestinationCategory.BUSINESS_SAAS, 0.99),
    "netsuite.com": (DestinationCategory.BUSINESS_SAAS, 0.99),
    "bloomberg.com": (DestinationCategory.BUSINESS_SAAS, 0.98),
}

def classify_destination(domain: str) -> DestinationClassification:
    """
    Classifies a domain using:
    1. Static / DuckDB dest_intel cache
    2. Local open LLM with Pydantic validation and prompt injection wrapping
    3. Update to DuckDB dest_intel table
    """
    clean_domain = domain.strip().lower()
    
    # 1. Check local dest_intel table
    try:
        con = get_connection()
        row = con.execute("SELECT category, confidence FROM dest_intel WHERE domain = ?", [clean_domain]).fetchone()
        con.close()
        if row:
            cat = DestinationCategory(row[0]) if row[0] in [c.value for c in DestinationCategory] else DestinationCategory.UNKNOWN
            return DestinationClassification(category=cat, confidence=float(row[1]), reasoning="Cached in dest_intel")
    except Exception:
        pass

    # 2. Check static rules
    if clean_domain in STATIC_RULES:
        cat, conf = STATIC_RULES[clean_domain]
        _save_to_intel(clean_domain, cat.value, conf, "static")
        return DestinationClassification(category=cat, confidence=conf, reasoning="Rule match")

    # 3. LLM classification
    llm = get_llm_client()
    untrusted_input = wrap_untrusted(f"Domain to classify: {clean_domain}", label="DOMAIN_INPUT")
    
    def fallback() -> DestinationClassification:
        # Heuristic fallback if LLM is offline and un-cached
        if any(x in clean_domain for x in ["cloud", "box", "drive", "share"]):
            cat = DestinationCategory.CLOUD_STORAGE
        elif any(x in clean_domain for x in ["git", "dev", "npm", "pip"]):
            cat = DestinationCategory.DEV_TOOL
        elif any(x in clean_domain for x in ["mail", "inbox"]):
            cat = DestinationCategory.PERSONAL_WEBMAIL
        elif any(x in clean_domain for x in ["chat", "msg", "slack", "discord"]):
            cat = DestinationCategory.MESSAGING
        elif any(x in clean_domain for x in ["crm", "erp", "saas", "work", "corp"]):
            cat = DestinationCategory.BUSINESS_SAAS
        else:
            cat = DestinationCategory.UNKNOWN
        return DestinationClassification(category=cat, confidence=0.75, reasoning="Offline heuristic fallback")

    result = llm.call_structured(
        component="dest_classifier",
        system_prompt=DEST_CLASSIFIER_PROMPT,
        user_input=untrusted_input,
        response_model=DestinationClassification,
        input_ref=clean_domain,
        fallback_factory=fallback
    )
    
    _save_to_intel(clean_domain, result.category.value, result.confidence, "llm")
    return result

def _save_to_intel(domain: str, category: str, confidence: float, source: str):
    try:
        con = get_connection()
        con.execute(
            """
            INSERT OR REPLACE INTO dest_intel (domain, category, confidence, source, classified_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [domain, category, confidence, source, datetime.now(timezone.utc)]
        )
        con.close()
    except Exception:
        pass

if __name__ == "__main__":
    test_domains = [
        "dropbox.com",
        "pastebin.com",
        "protonmail.com",
        "slack.com",
        "github.com",
        "salesforce.com",
        "megashare-demo.net",
        "unknown-suspicious-server.io",
        "registry.npmjs.org",
        "workday.com"
    ]
    print(f"Testing Destination Classifier on {len(test_domains)} domains:")
    for d in test_domains:
        res = classify_destination(d)
        print(f"  {d:32} -> {res.category.value:18} (conf: {res.confidence:.2f})")
