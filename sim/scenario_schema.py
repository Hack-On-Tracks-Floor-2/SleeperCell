from typing import List, Optional, Literal
from pydantic import BaseModel, Field

class DestinationConfig(BaseModel):
    domain: str
    category: str = "cloud_storage"
    first_seen: bool = True

class Phase(BaseModel):
    stage: Literal["access", "collection", "exfiltration", "cover_up"]
    start_day: int = Field(ge=1, description="Day number within the simulation period")
    duration_days: int = Field(ge=1, default=1)
    internal_read_mb_per_day: Optional[float] = None
    upload_mb: Optional[float] = None
    hours: List[int] = Field(default_factory=lambda: [9, 17], description="[start_hour, end_hour] in 24h format")
    destination: Optional[DestinationConfig] = None
    protocol: str = "https"
    pattern: Literal["burst", "drip", "tunnel", "normal"] = "burst"

class Actor(BaseModel):
    role: str
    count: int = 1
    flags: List[str] = Field(default_factory=list) # e.g. notice_period, privileged, external_vendor

class Evasion(BaseModel):
    padding: float = 0.0
    jitter: float = 0.0
    chunk_mb: Optional[float] = None

class ScenarioLabels(BaseModel):
    is_malicious: bool = True
    split: Literal["train", "test", "heldout"] = "train"

class Scenario(BaseModel):
    scenario_id: str
    description: str
    actor: Actor
    phases: List[Phase]
    evasion: Evasion = Field(default_factory=Evasion)
    labels: ScenarioLabels = Field(default_factory=ScenarioLabels)
