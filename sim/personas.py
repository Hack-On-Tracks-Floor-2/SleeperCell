from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Persona:
    role: str
    department: str
    name: str
    daily_mb_mean: float
    daily_mb_std: float
    work_start_hour: int
    work_end_hour: int
    typical_destinations: List[str]
    flags: List[str] = field(default_factory=list)

GOLDEN_SEED_PERSONAS: List[Persona] = [
    Persona(
        role="Senior Financial Analyst",
        department="Finance",
        name="Elena Rostova",
        daily_mb_mean=80.0,
        daily_mb_std=15.0,
        work_start_hour=9,
        work_end_hour=18,
        typical_destinations=[
            "netsuite.com",
            "bloomberg.com",
            "microsoft365.com",
            "sharepoint.internal.corp",
            "workday.com"
        ],
        flags=["notice_period"] # The insider actor
    ),
    Persona(
        role="Senior Backend Engineer",
        department="Dev",
        name="Marcus Vance",
        daily_mb_mean=450.0,
        daily_mb_std=90.0,
        work_start_hour=10,
        work_end_hour=19,
        typical_destinations=[
            "github.com",
            "registry.npmjs.org",
            "pypi.org",
            "aws.amazon.com",
            "datadoghq.com",
            "gitlab.internal.corp"
        ],
        flags=["privileged"]
    ),
    Persona(
        role="HR Business Partner",
        department="HR",
        name="Sarah Jenkins",
        daily_mb_mean=45.0,
        daily_mb_std=8.0,
        work_start_hour=8,
        work_end_hour=17,
        typical_destinations=[
            "workday.com",
            "greenhouse.io",
            "microsoft365.com",
            "docu-sign.net",
            "slack.com"
        ],
        flags=[]
    ),
    Persona(
        role="Enterprise Account Executive",
        department="Sales",
        name="David Sterling",
        daily_mb_mean=120.0,
        daily_mb_std=30.0,
        work_start_hour=8,
        work_end_hour=18,
        typical_destinations=[
            "salesforce.com",
            "zoom.us",
            "hubspot.com",
            "linkedin.com",
            "gong.io"
        ],
        flags=[]
    ),
    Persona(
        role="Site Reliability Engineer",
        department="Ops",
        name="Aisha Patel",
        daily_mb_mean=350.0,
        daily_mb_std=75.0,
        work_start_hour=9,
        work_end_hour=18,
        typical_destinations=[
            "grafana.net",
            "aws.amazon.com",
            "pagerduty.com",
            "cloudflare.com",
            "vault.internal.corp"
        ],
        flags=["privileged"]
    )
]
