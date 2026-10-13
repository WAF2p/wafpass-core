"""PDF report generator for WAF++ PASS using ReportLab."""

from __future__ import annotations

import hashlib
import io
import os
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from PIL import Image as _PILImage, ImageDraw as _PILDraw, ImageFilter as _PILFilter
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    HRFlowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether
from reportlab.platypus.tableofcontents import TableOfContents

from wafpass import __version__
from wafpass.models import ControlResult, Report
from wafpass.schema import ValidationEnvelopeSchema

# ── Logo path (resolved relative to this file so it works from any cwd) ───────
_LOGO_PATH = str(
    Path(__file__).parent.parent.parent
    / "waf2p.github.io" / "images" / "WAFpp_upscaled_1000.png"
)
# Pre-load once so ImageReader doesn't re-open on every page render
try:
    _LOGO_IMG = ImageReader(_LOGO_PATH)
except Exception:
    _LOGO_IMG = None  # graceful fallback if image not found

# ── Regulatory logos directory ────────────────────────────────────────────────
# Allow operators (e.g. the Docker image) to mount or copy logos under a
# well-known path, while keeping the source-tree default for local runs.
_REG_LOGOS_DIR = Path(
    os.environ.get("WAFPASS_ASSETS_DIR", Path(__file__).parent.parent / "assets")
) / "regulatory"

# Cache of loaded regulatory logo ImageReaders (None means image not found)
_REG_LOGO_CACHE: dict[str, "ImageReader | None"] = {}


def _reg_logo(framework: str) -> "ImageReader | None":
    """Return an ImageReader for the given regulatory framework, or None."""
    if framework in _REG_LOGO_CACHE:
        return _REG_LOGO_CACHE[framework]
    slug = framework.lower()
    for ch in " /:().,":
        slug = slug.replace(ch, "_")
    # Remove duplicate underscores
    while "__" in slug:
        slug = slug.replace("__", "_")
    slug = slug.strip("_")
    img = None
    for ext in ("png", "jpg", "jpeg", "svg"):
        candidate = _REG_LOGOS_DIR / f"{slug}.{ext}"
        if candidate.exists():
            try:
                img = ImageReader(str(candidate))
            except Exception:
                img = None
            break
    _REG_LOGO_CACHE[framework] = img
    return img


# Palette of badge background colors cycling for frameworks without logos
_BADGE_COLORS = [
    colors.HexColor("#2b7fff"),  # blue
    colors.HexColor("#7c3aed"),  # violet
    colors.HexColor("#0891b2"),  # cyan
    colors.HexColor("#059669"),  # emerald
    colors.HexColor("#d97706"),  # amber
    colors.HexColor("#dc2626"),  # red
    colors.HexColor("#0f172a"),  # navy
    colors.HexColor("#be185d"),  # pink
]

# ── Brand palette ─────────────────────────────────────────────────────────────
C_NAVY     = colors.HexColor("#0f172a")
C_BLUE     = colors.HexColor("#2b7fff")
C_BLUE_LT  = colors.HexColor("#dbeafe")
C_GREEN    = colors.HexColor("#22c55e")
C_GREEN_LT = colors.HexColor("#dcfce7")
C_RED      = colors.HexColor("#ef4444")
C_RED_LT   = colors.HexColor("#fee2e2")
C_ORANGE   = colors.HexColor("#f97316")
C_ORANGE_LT= colors.HexColor("#ffedd5")
C_YELLOW   = colors.HexColor("#eab308")
C_YELLOW_LT= colors.HexColor("#fef9c3")
C_GREY     = colors.HexColor("#64748b")
C_GREY_LT  = colors.HexColor("#f1f5f9")
C_BORDER   = colors.HexColor("#e2e8f0")
C_WHITE    = colors.white
C_DARK     = colors.HexColor("#1e293b")
C_PURPLE   = colors.HexColor("#7c3aed")
C_PURPLE_LT= colors.HexColor("#ede9fe")

PAGE_W, PAGE_H = A4
MARGIN     = 2.0 * cm
CONTENT_W  = PAGE_W - 2 * MARGIN

SEVERITY_COLORS: dict[str, tuple] = {
    "critical": (C_RED,    C_RED_LT),
    "high":     (C_ORANGE, C_ORANGE_LT),
    "medium":   (C_YELLOW, C_YELLOW_LT),
    "low":      (C_BLUE,   C_BLUE_LT),
}
STATUS_COLORS: dict[str, tuple] = {
    "PASS":   (C_GREEN,  C_GREEN_LT),
    "FAIL":   (C_RED,    C_RED_LT),
    "SKIP":   (C_GREY,   C_GREY_LT),
    "WAIVED": (C_PURPLE, C_PURPLE_LT),
}
STATUS_ICON = {"PASS": "✓", "FAIL": "✗", "SKIP": "─", "WAIVED": "○"}

# ── Risk & Financial impact constants ─────────────────────────────────────────

_SEV_WEIGHTS: dict[str, int] = {
    "critical": 10, "high": 6, "medium": 3, "low": 1,
}

# Estimated USD exposure per single failing control, by severity
# Source basis: IBM Cost of a Data Breach Report 2024 ($4.88M avg) + Gartner
_SEV_EXPOSURE_USD: dict[str, tuple[int, int]] = {
    "critical": (500_000, 5_000_000),
    "high":     (50_000,  500_000),
    "medium":   (5_000,   50_000),
    "low":      (500,     5_000),
}

# Risk context per pillar: (short category label, risk description)
_PILLAR_RISK_CONTEXT: dict[str, tuple[str, str]] = {
    "sovereign":    ("Regulatory & Compliance",  "Data residency violations, GDPR/NIS2 fines"),
    "security":     ("Breach & Incident",        "Data breach costs, incident response, forensics"),
    "cost":         ("Financial Waste",          "Over-provisioning, unmanaged commitments, waste"),
    "reliability":  ("Availability & Downtime",  "SLA breaches, service disruption, recovery costs"),
    "operations":   ("Operational Risk",         "Audit gaps, manual toil, remediation overhead"),
    "architecture": ("Technical Debt",           "Re-architecture spend, vendor lock-in migration"),
    "governance":   ("Governance & Audit",       "Compliance gaps, board-level findings, penalties"),
}


# ── Per-pillar risk type & exposure ranges ────────────────────────────────────
# Each pillar has its own risk category and appropriate exposure multipliers.
# Sources: GDPR Art.83, IBM Breach Report 2024, Gartner downtime benchmarks, CSRD.
_PILLAR_EXPOSURE_USD: dict[str, tuple] = {
    # pillar: (risk_type_label, risk_description, {severity: (min_usd, max_usd)})
    "security":     ("Breach & Regulatory",
                     "Data breach response, GDPR/NIS2 fines, forensics, notification costs",
                     {"critical": (500_000, 5_000_000), "high": (50_000, 500_000),
                      "medium": (5_000, 50_000), "low": (500, 5_000)}),
    "sovereign":    ("Regulatory Fine (GDPR Art. 83)",
                     "Up to €20M or 4% global turnover — GDPR Article 83(5) tier",
                     {"critical": (200_000, 2_000_000), "high": (50_000, 500_000),
                      "medium": (10_000, 100_000), "low": (1_000, 10_000)}),
    "cost":         ("Operational Waste",
                     "Direct cloud spend waste — over-provisioned resources, unmanaged lifecycle",
                     {"critical": (20_000, 200_000), "high": (5_000, 50_000),
                      "medium": (1_000, 10_000), "low": (200, 2_000)}),
    "reliability":  ("Service Availability",
                     "SLA breach costs — Gartner avg enterprise downtime $5,600/min",
                     {"critical": (100_000, 1_000_000), "high": (20_000, 200_000),
                      "medium": (5_000, 50_000), "low": (500, 5_000)}),
    "operations":   ("Operational Efficiency",
                     "Incident MTTR overhead, manual toil cost, audit remediation spend",
                     {"critical": (20_000, 100_000), "high": (5_000, 50_000),
                      "medium": (1_000, 10_000), "low": (200, 2_000)}),
    "performance":  ("Performance SLA Breach",
                     "Customer churn, SLA penalty payouts, support escalation costs",
                     {"critical": (50_000, 500_000), "high": (10_000, 100_000),
                      "medium": (2_000, 20_000), "low": (200, 2_000)}),
    "sustainability": ("CSRD / ESG Reporting Risk",
                       "CSRD non-compliance penalties, ESG investor exposure, reputational cost",
                       {"critical": (50_000, 200_000), "high": (10_000, 100_000),
                        "medium": (2_000, 20_000), "low": (500, 5_000)}),
}

# ── Root cause patterns for architectural analysis ────────────────────────────
# Each pattern matches a class of finding by regex on the check result message.
# effort_days is the estimated engineering effort to fix all instances at once.
_ROOT_CAUSE_PATTERNS: list[dict] = [
    {
        "id":          "log_retention",
        "title":       "CloudWatch log group retention not configured",
        "fix":         "Add retention_in_days = 90 to all aws_cloudwatch_log_group resources "
                       "(or your required minimum). A single locals block and for_each loop covers all groups.",
        "effort_days": 0.5,
        "regexes":     [r"retention_in_days", r"Log group retention", r"retention.*log"],
    },
    {
        "id":          "missing_tags",
        "title":       "Mandatory cost/governance tags missing on resources",
        "fix":         "Introduce a shared tags local (cost-center, owner, environment, workload) "
                       "and reference it in every resource's tags block, or use a tagging Terraform module.",
        "effort_days": 1.0,
        "regexes":     [r"is missing the", r"Azure resource is missing", r"EC2 instance is missing",
                        r"missing.*tag", r"cost-center"],
    },
    {
        "id":          "alarm_config",
        "title":       "CloudWatch alarm configuration incomplete",
        "fix":         "Standardise all alarm definitions: set alarm_description, evaluation_periods >= 3, "
                       "and alarm_actions with a valid SNS topic ARN. A shared alarm module enforces this.",
        "effort_days": 1.5,
        "regexes":     [r"CloudWatch alarm", r"alarm description", r"Alarm must evaluate",
                        r"alarm_actions", r"alarm must have"],
    },
    {
        "id":          "encryption_rest",
        "title":       "Encryption at rest not enforced on data stores",
        "fix":         "Enable KMS encryption on aws_db_instance (storage_encrypted), "
                       "aws_dynamodb_table (server_side_encryption), aws_elasticache_cluster, "
                       "and all aws_s3_bucket resources.",
        "effort_days": 2.0,
        "regexes":     [r"Data-storing resource MUST", r"encryption", r"kms_key_id"],
    },
    {
        "id":          "secrets_rotation",
        "title":       "Secrets Manager rotation not configured",
        "fix":         "Enable automatic rotation on all aws_secretsmanager_secret resources "
                       "by setting rotation_rules and linking a Lambda rotation function.",
        "effort_days": 1.0,
        "regexes":     [r"Secrets Manager secret", r"rotation_rules", r"secret rotation"],
    },
    {
        "id":          "iam_baseline",
        "title":       "IAM & KMS account-level security baseline not configured",
        "fix":         "Apply a compliant aws_iam_account_password_policy (min 14 chars, MFA, rotation). "
                       "Set deletion_window_in_days >= 14 on aws_kms_key resources.",
        "effort_days": 0.5,
        "regexes":     [r"IAM password policy", r"password policy", r"KMS key deletion"],
    },
    {
        "id":          "storage_config",
        "title":       "S3 versioning disabled and EBS volumes using deprecated gp2",
        "fix":         "Enable versioning on all S3 state buckets. "
                       "Change volume_type from gp2 to gp3 on all aws_ebs_volume and launch template block devices.",
        "effort_days": 0.5,
        "regexes":     [r"versioning", r"gp2", r"EBS volume"],
    },
    {
        "id":          "vpc_endpoints",
        "title":       "VPC endpoint configuration non-compliant",
        "fix":         "Set vpc_endpoint_type = \"Interface\" and enable private_dns_enabled = true "
                       "on all aws_vpc_endpoint resources.",
        "effort_days": 0.5,
        "regexes":     [r"VPC endpoint", r"vpc_endpoint_type", r"S3 VPC Endpoint"],
    },
    {
        "id":          "lambda_config",
        "title":       "Lambda function observability and sizing not configured",
        "fix":         "Set tracing_config { mode = \"Active\" } and right-size memory_size "
                       "on all aws_lambda_function resources.",
        "effort_days": 0.5,
        "regexes":     [r"Lambda tracing", r"Lambda memory_size", r"tracing mode"],
    },
    {
        "id":          "lock_in",
        "title":       "High lock-in cloud-native services used without exit strategy",
        "fix":         "Document a portability strategy for proprietary services (Kinesis, DynamoDB). "
                       "Consider abstraction layers or open-source equivalents.",
        "effort_days": 5.0,
        "regexes":     [r"High lock-in resource", r"lock.in", r"portability"],
    },
]


# ── World map constants ───────────────────────────────────────────────────────

_MAP_LAT_MIN, _MAP_LAT_MAX = -80.0, 80.0
_MAP_LON_MIN, _MAP_LON_MAX = -180.0, 180.0

# Fallback ReportLab colors (used only when PIL is unavailable)
_MAP_OCEAN   = colors.HexColor("#0d1b2e")
_MAP_LAND    = colors.HexColor("#1e3a5f")
_MAP_BORDER  = colors.HexColor("#2d5a8e")
_MAP_GRID    = colors.HexColor("#121e30")
_MAP_OUTLINE = colors.HexColor("#2d5a8e")

_PROVIDER_DOT_COLORS: dict[str, "colors.Color"] = {
    "aws":      colors.HexColor("#f97316"),
    "azure":    colors.HexColor("#2b7fff"),
    "gcp":      colors.HexColor("#22c55e"),
    "alicloud": colors.HexColor("#ff6a00"),
    "yandex":   colors.HexColor("#fcdb03"),
    "oci":      colors.HexColor("#c74634"),
}

# ── PIL color palette (modern dark theme) ─────────────────────────────────────
_PIL_C_OCEAN  = (10,  22,  46)   # deep navy
_PIL_C_LAND   = (38,  62,  95)   # slate blue
_PIL_C_BORDER = (58,  92, 132)   # coastline highlight
_PIL_C_GRID   = (16,  30,  55)   # barely-visible grid
_PIL_C_EQ     = (26,  48,  78)   # equator (slightly brighter)
_PIL_C_FRAME  = (55,  88, 126)   # map frame border

_PIL_PROV_RGB: dict[str, tuple[int, int, int]] = {
    "aws":      (249, 115,  22),
    "azure":    ( 43, 127, 255),
    "gcp":      ( 34, 197,  94),
    "alicloud": (255, 106,   0),
    "yandex":   (252, 219,   3),
    "oci":      (199,  70,  52),
}

# Continent polygons as (lon, lat) lists — significantly more detailed than
# the old version, with separate landmasses for cleaner polygon fills.
_CONTINENT_POLYS: list[list[tuple[float, float]]] = [

    # ── North America (with Florida peninsula + Gulf Coast) ────────────────────
    [(-168,71),(-160,66),(-152,60),(-145,60),(-137,59),(-130,54),
     (-126,50),(-124,48),(-124,46),(-124,42),(-124,37),(-120,34),
     (-117,32),(-115,31),(-110,29),(-106,23),(-100,20),(-95,16),
     (-90,16),(-87,14),(-83,10),(-77, 8),(-76,10),(-83,10),
     (-85,24),(-87,30),(-85,30),(-82,30),(-81,25),(-80,24),
     (-80,27),(-81,32),(-79,33),(-76,35),(-75,37),(-73,41),
     (-70,42),(-69,44),(-67,45),(-65,44),(-60,47),(-55,47),
     (-53,47),(-53,50),(-55,52),(-60,55),(-64,58),(-68,63),
     (-72,66),(-75,72),(-95,74),(-115,76),(-130,70),(-143,68),
     (-152,68),(-160,66),(-168,71)],

    # ── Greenland ─────────────────────────────────────────────────────────────
    [(-44,60),(-40,65),(-36,70),(-22,76),(-18,83),(-30,84),
     (-45,83),(-56,76),(-62,73),(-56,68),(-50,64),(-44,60)],

    # ── Iceland ───────────────────────────────────────────────────────────────
    [(-25,64),(-20,63),(-14,64),(-13,66),(-18,67),(-24,66),(-25,64)],

    # ── South America ─────────────────────────────────────────────────────────
    [(-80,12),(-77, 8),(-75, 2),(-76,-2),(-78,-5),(-80,-14),
     (-76,-20),(-72,-25),(-68,-35),(-65,-45),(-66,-55),(-68,-55),
     (-70,-50),(-72,-42),(-65,-30),(-60,-23),(-52,-28),(-46,-23),
     (-40,-15),(-38,-5),(-40, 0),(-50, 5),(-60, 8),(-67,12),
     (-72,12),(-75,10),(-80,12)],

    # ── Iberian Peninsula ─────────────────────────────────────────────────────
    [(-9,36),(-9,38),(-9,44),(-4,44),(-1,44),(0,43),(3,43),(3,37),(0,36),(-5,36),(-9,36)],

    # ── Main Europe (France, Low Countries, Germany, Balkans) ─────────────────
    [(3,43),(0,43),(-1,44),(-4,44),(-1,46),(2,47),(3,51),(5,52),
     (7,54),(10,55),(14,54),(16,54),(18,56),(20,54),(22,54),
     (24,56),(26,56),(28,54),(28,52),(24,50),(22,50),(22,48),
     (24,48),(26,48),(28,44),(30,46),(34,42),(36,42),(36,40),
     (30,44),(26,42),(24,44),(22,44),(20,44),(18,46),(16,48),
     (14,52),(12,51),(10,51),(8,48),(6,46),(5,43),(3,43)],

    # ── Italian Peninsula ─────────────────────────────────────────────────────
    [(8,44),(10,44),(12,44),(14,44),(16,40),(16,37),(14,37),
     (12,37),(10,38),(8,40),(7,43),(8,44)],

    # ── Scandinavian Peninsula ────────────────────────────────────────────────
    [(10,55),(10,57),(8,58),(7,62),(10,63),(14,65),(16,68),
     (18,69),(22,70),(26,72),(28,72),(26,70),(30,65),(28,60),
     (24,58),(22,56),(20,54),(18,56),(16,56),(14,56),(12,56),(10,55)],

    # ── Great Britain ─────────────────────────────────────────────────────────
    [(-5,50),(-3,50),(-1,51),(1,51),(0,52),(-1,54),(-2,57),
     (-5,58),(-6,56),(-5,54),(-4,51),(-5,50)],

    # ── Ireland ───────────────────────────────────────────────────────────────
    [(-10,52),(-7,52),(-6,53),(-7,55),(-8,55),(-10,54),(-10,52)],

    # ── Africa ────────────────────────────────────────────────────────────────
    [(-17,15),(-15,10),(-10, 5),(-2, 5),(4, 4),(8, 4),(10, 2),
     (12,-4),(12,-10),(14,-20),(18,-28),(20,-35),(26,-35),
     (32,-30),(36,-22),(40,-10),(42, 0),(42,10),(40,16),
     (44,12),(50,12),(44,20),(38,22),(36,28),(33,31),
     (25,32),(10,37),(0,37),(-10,36),(-17,28),(-17,15)],

    # ── Arabian Peninsula ─────────────────────────────────────────────────────
    [(37,30),(37,22),(40,14),(44,12),(48,14),(52,16),
     (56,22),(58,22),(58,24),(55,24),(52,24),(48,24),
     (44,24),(40,24),(38,26),(37,30)],

    # ── Indian Subcontinent ───────────────────────────────────────────────────
    [(65,25),(68,24),(72,22),(74,20),(77, 8),(80,10),
     (80,16),(77,20),(80,24),(84,27),(87,28),(90,22),
     (92,22),(95,18),(92,18),(90,22),(87,28),(84,27),
     (80,28),(76,32),(74,32),(72,22),(68,24)],

    # ── Asia main (Turkey → Russia Pacific coast) ──────────────────────────────
    [(26,40),(36,42),(40,38),(48,30),(60,26),(65,25),
     (72,22),(74,20),(77, 8),(80,10),(80,16),(77,20),
     (80,24),(84,27),(87,28),(90,22),(92,22),(95,18),
     (98,10),(100,5),(104,2),(110,2),(104,0),(100,2),
     (103,4),(105,10),(108,16),(110,20),(115,20),
     (118,24),(122,30),(122,35),(125,36),(130,35),
     (133,35),(135,40),(138,44),(140,46),(145,50),
     (140,56),(135,60),(130,65),(120,68),
     (100,73),(80,73),(60,70),(50,65),(40,65),
     (30,70),(28,65),(25,60),(35,55),(40,50),
     (36,44),(30,44),(26,40)],

    # ── Indochina Peninsula ───────────────────────────────────────────────────
    [(100,18),(102,16),(104,14),(104, 6),(102, 4),(100, 4),
     (100,10),(102,14),(100,18)],

    # ── Japan (Honshu) ────────────────────────────────────────────────────────
    [(130,32),(132,34),(136,35),(138,36),(140,38),
     (141,41),(140,44),(138,43),(135,42),(134,38),
     (133,35),(131,33),(130,32)],

    # ── Australia ─────────────────────────────────────────────────────────────
    [(114,-22),(118,-16),(122,-14),(128,-14),(132,-12),
     (136,-12),(138,-14),(140,-18),(145,-15),(148,-20),
     (150,-24),(152,-28),(153,-30),(151,-33),(148,-38),
     (145,-40),(136,-35),(130,-33),(120,-34),(115,-34),
     (114,-30),(114,-22)],

    # ── New Zealand (South Island) ────────────────────────────────────────────
    [(166,-46),(168,-46),(171,-42),(173,-38),(172,-37),
     (170,-38),(168,-44),(166,-46)],
]

# Region → (lat, lon) — canonical Terraform region identifiers (lowercase)
_REGION_COORDS: dict[str, tuple[float, float]] = {
    # ── AWS ──────────────────────────────────────────────────────────────────
    "us-east-1":      (37.77, -77.42),   "us-east-2":      (39.96, -82.99),
    "us-west-1":      (37.33, -121.89),  "us-west-2":      (45.51, -122.68),
    "af-south-1":     (-33.92, 18.42),
    "ap-east-1":      (22.32, 114.17),
    "ap-south-1":     (19.08, 72.88),    "ap-south-2":     (17.39, 78.49),
    "ap-southeast-1": (1.35, 103.82),    "ap-southeast-2": (-33.87, 151.21),
    "ap-southeast-3": (-6.21, 106.85),   "ap-southeast-4": (-37.81, 144.96),
    "ap-northeast-1": (35.68, 139.65),   "ap-northeast-2": (37.57, 126.98),
    "ap-northeast-3": (34.69, 135.50),
    "ca-central-1":   (45.42, -75.70),   "ca-west-1":      (51.04, -114.07),
    "eu-central-1":   (50.11, 8.68),     "eu-central-2":   (47.38, 8.54),
    "eu-west-1":      (53.35, -6.26),    "eu-west-2":      (51.51, -0.13),
    "eu-west-3":      (48.86, 2.35),     "eu-south-1":     (45.47, 9.19),
    "eu-south-2":     (40.42, -3.70),    "eu-north-1":     (59.33, 18.07),
    "il-central-1":   (32.09, 34.78),
    "me-central-1":   (25.20, 55.27),    "me-south-1":     (26.07, 50.56),
    "sa-east-1":      (-23.55, -46.63),
    # ── Azure ─────────────────────────────────────────────────────────────────
    "eastus":             (37.77, -77.42),   "eastus2":            (36.67, -78.39),
    "westus":             (37.33, -121.89),  "westus2":            (47.20, -119.85),
    "westus3":            (33.45, -112.07),  "centralus":          (41.59, -93.62),
    "northcentralus":     (41.88, -87.63),   "southcentralus":     (29.42, -98.49),
    "westcentralus":      (40.89, -110.23),
    "northeurope":        (53.35, -6.26),    "westeurope":         (52.37, 4.90),
    "uksouth":            (51.51, -0.13),    "ukwest":             (53.41, -2.99),
    "francecentral":      (48.86, 2.35),     "francesouth":        (43.83, 2.20),
    "germanywestcentral": (50.11, 8.68),     "germanynorth":       (53.07, 8.81),
    "switzerlandnorth":   (47.45, 8.45),     "switzerlandwest":    (46.20, 6.14),
    "norwayeast":         (59.91, 10.75),    "swedencentral":      (60.67, 17.14),
    "eastasia":           (22.32, 114.17),   "southeastasia":      (1.35, 103.82),
    "australiaeast":      (-33.87, 151.21),  "australiasoutheast": (-37.81, 144.96),
    "australiacentral":   (-35.31, 149.12),
    "japaneast":          (35.68, 139.65),   "japanwest":          (34.69, 135.50),
    "koreacentral":       (37.57, 126.98),   "koreasouth":         (35.18, 129.08),
    "centralindia":       (18.52, 73.86),    "southindia":         (12.97, 77.59),
    "westindia":          (19.08, 72.88),
    "brazilsouth":        (-23.55, -46.63),  "brazilsoutheast":    (-22.91, -43.17),
    "canadacentral":      (43.65, -79.38),   "canadaeast":         (46.81, -71.21),
    "southafricanorth":   (-25.73, 28.22),   "southafricawest":    (-33.92, 18.42),
    "uaenorth":           (25.20, 55.27),    "uaecentral":         (24.45, 54.38),
    # ── GCP ───────────────────────────────────────────────────────────────────
    "us-central1":             (41.26, -95.86),  "us-east1":              (33.20, -80.01),
    "us-east4":                (38.99, -77.36),  "us-east5":              (40.02, -75.10),
    "us-south1":               (32.78, -96.80),  "us-west1":              (45.59, -121.18),
    "us-west2":                (34.05, -118.24), "us-west3":              (40.76, -111.89),
    "us-west4":                (36.17, -115.14),
    "northamerica-northeast1": (45.50, -73.57),  "northamerica-northeast2": (43.65, -79.38),
    "southamerica-east1":      (-23.55, -46.63), "southamerica-west1":    (-33.45, -70.67),
    "europe-central2":         (52.23, 21.01),   "europe-north1":         (60.57, 27.19),
    "europe-southwest1":       (38.72, -9.14),   "europe-west1":          (50.45, 3.81),
    "europe-west2":            (51.51, -0.13),   "europe-west3":          (50.11, 8.68),
    "europe-west4":            (53.44, 6.84),    "europe-west6":          (47.38, 8.54),
    "europe-west8":            (45.46, 9.19),    "europe-west9":          (48.86, 2.35),
    "europe-west10":           (52.52, 13.41),   "europe-west12":         (45.07, 7.69),
    "asia-east1":              (24.05, 120.52),  "asia-east2":            (22.32, 114.17),
    "asia-northeast1":         (35.68, 139.65),  "asia-northeast2":       (34.69, 135.50),
    "asia-northeast3":         (37.57, 126.98),  "asia-south1":           (19.08, 72.88),
    "asia-south2":             (28.61, 77.21),   "asia-southeast1":       (1.35, 103.82),
    "asia-southeast2":         (-6.21, 106.85),
    "australia-southeast1":    (-33.87, 151.21), "australia-southeast2":  (-37.81, 144.96),
    "me-central1":             (25.20, 55.27),   "me-central2":           (25.20, 55.27),
    "me-west1":                (32.09, 34.78),   "africa-south1":         (-33.92, 18.42),
    # ── Alibaba Cloud ─────────────────────────────────────────────────────────
    "cn-hangzhou":     (30.25, 120.16),  "cn-shanghai":     (31.23, 121.47),
    "cn-beijing":      (39.91, 116.39),  "cn-shenzhen":     (22.54, 114.05),
    "cn-zhangjiakou":  (40.77, 114.88),  "cn-huhehaote":    (40.81, 111.65),
    "cn-wulanchabu":   (41.00, 113.09),  "cn-chengdu":      (30.57, 104.07),
    "cn-hongkong":     (22.32, 114.17),  "cn-nanjing":      (32.06, 118.78),
    "cn-fuzhou":       (26.07, 119.30),  "cn-guangzhou":    (23.13, 113.26),
    "cn-heyuan":       (23.73, 114.69),  "cn-wuhan":        (30.59, 114.31),
    "ap-southeast-3":  (3.14,  101.69),  "ap-southeast-6":  (14.60, 120.98),
    "ap-southeast-7":  (13.75, 100.52),  "me-east-1":       (25.20,  55.27),
    # ── Yandex Cloud ──────────────────────────────────────────────────────────
    "ru-central1":     (55.75,  37.61),
    # ── Oracle Cloud Infrastructure (OCI) ─────────────────────────────────────
    "us-phoenix-1":    (33.45, -112.07), "us-ashburn-1":    (39.03,  -77.49),
    "us-sanjose-1":    (37.34, -121.89), "us-chicago-1":    (41.88,  -87.63),
    "ca-toronto-1":    (43.65,  -79.38), "ca-montreal-1":   (45.50,  -73.57),
    "sa-saopaulo-1":   (-23.55, -46.63), "sa-vinhedo-1":    (-23.03, -47.01),
    "uk-london-1":     (51.51,   -0.13), "uk-cardiff-1":    (51.48,   -3.18),
    "eu-frankfurt-1":  (50.11,    8.68), "eu-amsterdam-1":  (52.37,    4.90),
    "eu-stockholm-1":  (59.33,   18.07), "eu-milan-1":      (45.47,    9.19),
    "eu-marseille-1":  (43.30,    5.37), "eu-paris-1":      (48.86,    2.35),
    "eu-madrid-1":     (40.42,   -3.70), "eu-jovanovac-1":  (44.01,   21.32),
    "ap-tokyo-1":      (35.68,  139.65), "ap-osaka-1":      (34.69,  135.50),
    "ap-seoul-1":      (37.57,  126.98), "ap-chuncheon-1":  (37.87,  127.72),
    "ap-mumbai-1":     (19.08,   72.88), "ap-hyderabad-1":  (17.39,   78.49),
    "ap-singapore-1":  (1.35,   103.82), "ap-singapore-2":  (1.35,   103.82),
    "ap-melbourne-1":  (-37.81, 144.96), "ap-sydney-1":     (-33.87, 151.21),
    "me-dubai-1":      (25.20,   55.27), "me-jeddah-1":     (21.49,   39.19),
    "me-abudhabi-1":   (24.45,   54.38), "af-johannesburg-1": (-26.20, 28.04),
    "il-jerusalem-1":  (31.77,   35.21), "mx-queretaro-1":  (20.59, -100.39),
    "mx-monterrey-1":  (25.69, -100.32),
}

# Human-readable labels for common regions
_REGION_LABELS: dict[str, str] = {
    "us-east-1": "N. Virginia, USA",       "us-east-2": "Ohio, USA",
    "us-west-1": "N. California, USA",     "us-west-2": "Oregon, USA",
    "af-south-1": "Cape Town, South Africa",
    "ap-east-1": "Hong Kong",              "ap-south-1": "Mumbai, India",
    "ap-south-2": "Hyderabad, India",
    "ap-southeast-1": "Singapore",         "ap-southeast-2": "Sydney, Australia",
    "ap-southeast-3": "Jakarta, Indonesia","ap-southeast-4": "Melbourne, Australia",
    "ap-northeast-1": "Tokyo, Japan",      "ap-northeast-2": "Seoul, South Korea",
    "ap-northeast-3": "Osaka, Japan",
    "ca-central-1": "Canada (Central)",    "ca-west-1": "Calgary, Canada",
    "eu-central-1": "Frankfurt, Germany",  "eu-central-2": "Zurich, Switzerland",
    "eu-west-1": "Ireland",                "eu-west-2": "London, UK",
    "eu-west-3": "Paris, France",          "eu-south-1": "Milan, Italy",
    "eu-south-2": "Madrid, Spain",         "eu-north-1": "Stockholm, Sweden",
    "il-central-1": "Tel Aviv, Israel",
    "me-central-1": "UAE",                 "me-south-1": "Bahrain",
    "sa-east-1": "São Paulo, Brazil",
    "eastus": "E. USA (Virginia)",         "eastus2": "E. USA 2 (Virginia)",
    "westus": "W. USA (California)",       "westus2": "W. USA 2 (Washington)",
    "westus3": "W. USA 3 (Arizona)",       "centralus": "Central USA (Iowa)",
    "northcentralus": "N. Central USA",    "southcentralus": "S. Central USA",
    "northeurope": "Ireland",              "westeurope": "Netherlands",
    "uksouth": "London, UK",               "ukwest": "Cardiff, UK",
    "francecentral": "Paris, France",      "germanywestcentral": "Frankfurt, Germany",
    "switzerlandnorth": "Zurich, Switzerland",
    "norwayeast": "Oslo, Norway",          "swedencentral": "Gävle, Sweden",
    "eastasia": "Hong Kong",              "southeastasia": "Singapore",
    "australiaeast": "Sydney, Australia",  "australiasoutheast": "Melbourne, Australia",
    "japaneast": "Tokyo, Japan",           "koreacentral": "Seoul, South Korea",
    "centralindia": "Pune, India",         "brazilsouth": "São Paulo, Brazil",
    "canadacentral": "Toronto, Canada",    "southafricanorth": "Johannesburg, SA",
    "uaenorth": "Dubai, UAE",
    "us-central1": "Iowa, USA",            "us-east1": "S. Carolina, USA",
    "us-east4": "N. Virginia, USA",        "us-west1": "Oregon, USA",
    "us-west2": "Los Angeles, USA",
    "northamerica-northeast1": "Montréal, Canada",
    "southamerica-east1": "São Paulo, Brazil",
    "europe-west1": "Belgium",             "europe-west2": "London, UK",
    "europe-west3": "Frankfurt, Germany",  "europe-west4": "Netherlands",
    "europe-west6": "Zurich, Switzerland", "europe-west9": "Paris, France",
    "europe-north1": "Finland",            "europe-central2": "Warsaw, Poland",
    "asia-east1": "Taiwan",                "asia-east2": "Hong Kong",
    "asia-northeast1": "Tokyo, Japan",     "asia-northeast3": "Seoul, South Korea",
    "asia-south1": "Mumbai, India",        "asia-southeast1": "Singapore",
    "asia-southeast2": "Jakarta, Indonesia",
    "australia-southeast1": "Sydney, Australia",
    "me-west1": "Tel Aviv, Israel",        "africa-south1": "Cape Town, SA",
    # Alibaba Cloud
    "cn-hangzhou":    "Hangzhou, China",    "cn-shanghai":    "Shanghai, China",
    "cn-beijing":     "Beijing, China",     "cn-shenzhen":    "Shenzhen, China",
    "cn-zhangjiakou": "Zhangjiakou, China", "cn-huhehaote":   "Hohhot, China",
    "cn-wulanchabu":  "Ulanqab, China",     "cn-chengdu":     "Chengdu, China",
    "cn-hongkong":    "Hong Kong, China",   "cn-nanjing":     "Nanjing, China",
    "cn-fuzhou":      "Fuzhou, China",      "cn-guangzhou":   "Guangzhou, China",
    "cn-heyuan":      "Heyuan, China",      "cn-wuhan":       "Wuhan, China",
    "ap-southeast-3": "Kuala Lumpur, Malaysia",
    "ap-southeast-6": "Manila, Philippines", "ap-southeast-7": "Bangkok, Thailand",
    "me-east-1":      "Dubai, UAE",
    # Yandex Cloud
    "ru-central1":    "Moscow, Russia",
    # Oracle Cloud Infrastructure
    "us-phoenix-1":   "Phoenix, USA",       "us-ashburn-1":   "Ashburn, USA",
    "us-sanjose-1":   "San Jose, USA",      "us-chicago-1":   "Chicago, USA",
    "ca-toronto-1":   "Toronto, Canada",    "ca-montreal-1":  "Montréal, Canada",
    "sa-saopaulo-1":  "São Paulo, Brazil",  "sa-vinhedo-1":   "Vinhedo, Brazil",
    "uk-london-1":    "London, UK",         "uk-cardiff-1":   "Cardiff, UK",
    "eu-frankfurt-1": "Frankfurt, Germany", "eu-amsterdam-1": "Amsterdam, Netherlands",
    "eu-stockholm-1": "Stockholm, Sweden",  "eu-milan-1":     "Milan, Italy",
    "eu-marseille-1": "Marseille, France",  "eu-paris-1":     "Paris, France",
    "eu-madrid-1":    "Madrid, Spain",      "eu-jovanovac-1": "Jovanovac, Serbia",
    "ap-tokyo-1":     "Tokyo, Japan",       "ap-osaka-1":     "Osaka, Japan",
    "ap-seoul-1":     "Seoul, South Korea", "ap-chuncheon-1": "Chuncheon, South Korea",
    "ap-mumbai-1":    "Mumbai, India",      "ap-hyderabad-1": "Hyderabad, India",
    "ap-singapore-1": "Singapore",          "ap-singapore-2": "Singapore (2)",
    "ap-melbourne-1": "Melbourne, Australia","ap-sydney-1":    "Sydney, Australia",
    "me-dubai-1":     "Dubai, UAE",         "me-jeddah-1":    "Jeddah, Saudi Arabia",
    "me-abudhabi-1":  "Abu Dhabi, UAE",     "af-johannesburg-1": "Johannesburg, SA",
    "il-jerusalem-1": "Jerusalem, Israel",  "mx-queretaro-1": "Querétaro, Mexico",
    "mx-monterrey-1": "Monterrey, Mexico",
}


# ── Tile basemap constants ────────────────────────────────────────────────────

_MAP_TILE_ZOOM = 2        # zoom 2 → 4×4 = 16 tiles → 1024×1024 px world image
_TILE_SIZE_PX  = 256
_TILE_LAT_MAX  =  65.0    # clip polar extremes; every cloud region is within ±65°
_TILE_LAT_MIN  = -65.0


def _mercator_y_frac(lat: float) -> float:
    """Web Mercator y-fraction [0=top, 1=bottom] for *lat* in degrees."""
    import math
    lat_r = math.radians(max(-85.0, min(85.0, lat)))
    return (1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0


def _fetch_tile_basemap(zoom: int = _MAP_TILE_ZOOM) -> "_PILImage.Image | None":
    """Download CARTO dark-matter tiles and return a stitched PIL Image.

    Tile source: CARTO dark_all (© CARTO, © OpenStreetMap contributors, ODbL).
    Returns None when PIL/requests are unavailable or every tile request fails.
    """
    if not _PIL_AVAILABLE:
        return None
    try:
        import requests
    except ImportError:
        return None

    n       = 2 ** zoom
    full_px = n * _TILE_SIZE_PX
    canvas  = _PILImage.new("RGB", (full_px, full_px), _PIL_C_OCEAN)
    session = requests.Session()
    session.headers["User-Agent"] = (
        "waf-pass/1.0 (+https://github.com/WAF2p/waf--) PDF report generator"
    )
    any_ok = False
    for ty in range(n):
        for tx in range(n):
            url = f"https://a.basemaps.cartocdn.com/dark_all/{zoom}/{tx}/{ty}.png"
            try:
                resp = session.get(url, timeout=4)
                if resp.status_code == 200:
                    tile = _PILImage.open(io.BytesIO(resp.content)).convert("RGB")
                    canvas.paste(tile, (tx * _TILE_SIZE_PX, ty * _TILE_SIZE_PX))
                    any_ok = True
            except Exception:
                pass
    return canvas if any_ok else None


def _render_world_map_pil(
    width_pt: float,
    height_pt: float,
    regions: list[tuple[str, str, str | None]],
) -> "io.BytesIO | None":
    """Render a modern world map as a BytesIO PNG.

    Primary path:  CARTO dark-matter OSM tile basemap (fetched at runtime).
    Fallback path: hand-drawn polygon map using the same glow/dot rendering.
    Returns None if PIL is unavailable.
    """
    if not _PIL_AVAILABLE:
        return None

    SUPER        = 2
    DPI          = 200
    PTS_PER_INCH = 72.0
    out_w = max(200, int(width_pt  / PTS_PER_INCH * DPI))
    out_h = max(100, int(height_pt / PTS_PER_INCH * DPI))

    # ── Try tile basemap ───────────────────────────────────────────────────────
    tile_img = _fetch_tile_basemap(_MAP_TILE_ZOOM)

    if tile_img is not None:
        # Crop to the display latitude window, then upsample for glow rendering
        full_px    = tile_img.width                    # 1024
        y_top_frac = _mercator_y_frac(_TILE_LAT_MAX)
        y_bot_frac = _mercator_y_frac(_TILE_LAT_MIN)
        y_top_px   = int(y_top_frac * full_px)
        y_bot_px   = int(y_bot_frac * full_px)
        cropped    = tile_img.crop((0, y_top_px, full_px, y_bot_px))
        base       = cropped.resize((out_w * SUPER, out_h * SUPER), _PILImage.LANCZOS)

        def lonlat_px(lon: float, lat: float) -> tuple[int, int]:
            """Mercator lon/lat → pixel in the supersampled canvas."""
            x     = int((lon + 180.0) / 360.0 * out_w * SUPER)
            y_f   = _mercator_y_frac(lat)
            y     = int((y_f - y_top_frac) / (y_bot_frac - y_top_frac) * out_h * SUPER)
            return x, y

    else:
        # ── Polygon fallback ──────────────────────────────────────────────────
        w_px = out_w * SUPER
        h_px = out_h * SUPER
        base = _PILImage.new("RGB", (w_px, h_px), _PIL_C_OCEAN)
        drw  = _PILDraw.Draw(base)

        def lonlat_px(lon: float, lat: float) -> tuple[int, int]:
            x = int((lon - _MAP_LON_MIN) / (_MAP_LON_MAX - _MAP_LON_MIN) * w_px)
            y = int((1.0 - (lat - _MAP_LAT_MIN) / (_MAP_LAT_MAX - _MAP_LAT_MIN)) * h_px)
            return x, y

        gw = max(1, SUPER // 2)
        for glon in range(-150, 181, 30):
            pts = [lonlat_px(glon, lat) for lat in range(-80, 81, 10)]
            for i in range(len(pts) - 1):
                drw.line([pts[i], pts[i + 1]], fill=_PIL_C_GRID, width=gw)
        for glat in range(-60, 61, 30):
            drw.line([lonlat_px(-180, glat), lonlat_px(180, glat)],
                     fill=_PIL_C_GRID, width=gw)
        drw.line([lonlat_px(-180, 0), lonlat_px(180, 0)], fill=_PIL_C_EQ, width=SUPER)
        for poly in _CONTINENT_POLYS:
            if len(poly) < 3:
                continue
            drw.polygon([lonlat_px(lon, lat) for lon, lat in poly],
                        fill=_PIL_C_LAND, outline=_PIL_C_BORDER)

    # ── Markers (same for both paths) ─────────────────────────────────────────
    w_super = out_w * SUPER
    h_super = out_h * SUPER
    markers: list[tuple[int, int, tuple[int, int, int]]] = []
    seen: set[tuple[str, str]] = set()
    for rname, prov, _ in regions:
        key = (rname.strip().lower(), prov.lower())
        if key in seen:
            continue
        seen.add(key)
        coords = _REGION_COORDS.get(rname.strip().lower())
        if not coords:
            continue
        lat, lon = coords
        xp, yp = lonlat_px(lon, lat)
        if not (0 <= xp < w_super and 0 <= yp < h_super):
            continue
        markers.append((xp, yp, _PIL_PROV_RGB.get(prov.lower(), (100, 116, 139))))

    # ── Glow layer ─────────────────────────────────────────────────────────────
    glow = _PILImage.new("RGBA", (w_super, h_super), (0, 0, 0, 0))
    gdrw = _PILDraw.Draw(glow)
    for xp, yp, c in markers:
        r_g = int(22 * SUPER)
        gdrw.ellipse([xp - r_g, yp - r_g, xp + r_g, yp + r_g], fill=(*c, 85))
    glow      = glow.filter(_PILFilter.GaussianBlur(radius=int(10 * SUPER)))
    base_rgba = _PILImage.alpha_composite(base.convert("RGBA"), glow)

    # ── Sharp dots ─────────────────────────────────────────────────────────────
    ddraw  = _PILDraw.Draw(base_rgba)
    r_halo = int(7 * SUPER)
    r_dot  = int(5 * SUPER)
    r_core = int(2 * SUPER)
    for xp, yp, c in markers:
        ddraw.ellipse([xp - r_halo, yp - r_halo, xp + r_halo, yp + r_halo],
                      fill=(255, 255, 255, 200))
        ddraw.ellipse([xp - r_dot,  yp - r_dot,  xp + r_dot,  yp + r_dot],
                      fill=(*c, 255))
        ddraw.ellipse([xp - r_core, yp - r_core, xp + r_core, yp + r_core],
                      fill=(255, 255, 255, 235))

    # ── Frame + downscale ──────────────────────────────────────────────────────
    result = base_rgba.convert("RGB")
    _PILDraw.Draw(result).rectangle(
        [0, 0, w_super - 1, h_super - 1], outline=_PIL_C_FRAME, width=max(1, SUPER)
    )
    final = result.resize((out_w, out_h), _PILImage.LANCZOS)

    buf = io.BytesIO()
    final.save(buf, format="PNG")
    buf.seek(0)
    return buf


def _risk_score(report: "Report") -> tuple[int, str, "colors.Color"]:
    """Return (score 0-100, label, colour) for the overall risk posture."""
    total_w = fail_w = 0
    for cr in report.results:
        w = _SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1)
        total_w += w
        if cr.status == "FAIL":
            fail_w += w
    score = int(fail_w / max(total_w, 1) * 100)
    if score >= 70:
        return score, "CRITICAL", C_RED
    if score >= 40:
        return score, "HIGH",     C_ORANGE
    if score >= 20:
        return score, "MEDIUM",   C_YELLOW
    return score, "LOW", C_GREEN


def _financial_exposure(
    report: "Report",
) -> tuple[int, int, dict[str, tuple[int, int, int]]]:
    """Return (total_min, total_max, {severity: (count, min, max)}) in USD."""
    breakdown: dict[str, list] = {}
    total_min = total_max = 0
    for cr in report.results:
        if cr.status != "FAIL":
            continue
        sev = (cr.control.severity or "low").lower()
        exp_min, exp_max = _SEV_EXPOSURE_USD.get(sev, (0, 0))
        total_min += exp_min
        total_max += exp_max
        if sev not in breakdown:
            breakdown[sev] = [0, 0, 0]
        breakdown[sev][0] += 1
        breakdown[sev][1] += exp_min
        breakdown[sev][2] += exp_max
    return total_min, total_max, {k: tuple(v) for k, v in breakdown.items()}


def _fmt_usd(n: int) -> str:
    """Format a USD integer as a compact string (e.g. $4.9M, $350K)."""
    if n >= 1_000_000:
        return f"${n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"${n / 1_000:.0f}K"
    return f"${n:,}"


def _pillar_scores(report: "Report") -> dict[str, int]:
    """Return {pillar: score_0_to_100} for all pillars in the report."""
    pd: dict[str, dict] = {}
    for cr in report.results:
        p = (cr.control.pillar or "unknown").lower()
        w = _SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1)
        if p not in pd:
            pd[p] = {"total_w": 0, "fail_w": 0}
        pd[p]["total_w"] += w
        if cr.status == "FAIL":
            pd[p]["fail_w"] += w
    return {p: int(d["fail_w"] / max(d["total_w"], 1) * 100) for p, d in pd.items()}


def _analyse_root_causes(report: "Report") -> list[dict]:
    """
    Match failing check results against root cause patterns.

    Returns a list of pattern dicts enriched with:
      - matched_controls: list of ControlResult
      - finding_count: int
      - score_impact: float (points dropped from risk score if fixed)
    """
    total_w = sum(
        _SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1)
        for cr in report.results
    )
    results: list[dict] = []
    for pat in _ROOT_CAUSE_PATTERNS:
        compiled = [re.compile(rx, re.IGNORECASE) for rx in pat["regexes"]]
        matched_crs: list = []
        finding_count = 0
        for cr in report.results:
            if cr.status != "FAIL":
                continue
            cr_hit = False
            for r in cr.results:
                if r.status == "FAIL":
                    if any(rx.search(r.message or "") for rx in compiled):
                        finding_count += 1
                        cr_hit = True
            if cr_hit and cr not in matched_crs:
                matched_crs.append(cr)
        if not matched_crs:
            continue
        fix_w = sum(_SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1) for cr in matched_crs)
        score_impact = fix_w / max(total_w, 1) * 100
        results.append({
            **pat,
            "matched_controls": matched_crs,
            "finding_count":    finding_count,
            "score_impact":     score_impact,
            "roi":              score_impact / max(pat["effort_days"], 0.1),
        })
    results.sort(key=lambda x: x["roi"], reverse=True)
    return results


def _financial_exposure_by_risk_type(report: "Report") -> list[dict]:
    """
    Return financial exposure segmented by pillar risk type.

    Each entry: {risk_type, description, pillar, fail_count, min_usd, max_usd}
    Sorted by max_usd descending.
    """
    aggregated: dict[str, dict] = {}
    for cr in report.results:
        if cr.status != "FAIL":
            continue
        pillar = (cr.control.pillar or "unknown").lower()
        sev    = (cr.control.severity or "low").lower()
        entry  = _PILLAR_EXPOSURE_USD.get(pillar)
        if entry is None:
            # Fallback: use security ranges
            entry = _PILLAR_EXPOSURE_USD["security"]
        risk_type, desc, ranges = entry
        exp_min, exp_max = ranges.get(sev, (0, 0))
        if risk_type not in aggregated:
            aggregated[risk_type] = {
                "risk_type":   risk_type,
                "description": desc,
                "pillars":     set(),
                "fail_count":  0,
                "min_usd":     0,
                "max_usd":     0,
            }
        aggregated[risk_type]["pillars"].add(pillar.title())
        aggregated[risk_type]["fail_count"] += 1
        aggregated[risk_type]["min_usd"]    += exp_min
        aggregated[risk_type]["max_usd"]    += exp_max
    rows = list(aggregated.values())
    for r in rows:
        r["pillars"] = ", ".join(sorted(r["pillars"]))
    rows.sort(key=lambda x: x["max_usd"], reverse=True)
    return rows


class _TOCEntry(Flowable):
    """Zero-height, invisible flowable that registers a TOC entry at build time."""

    def __init__(self, level: int, text: str) -> None:
        Flowable.__init__(self)
        self.width  = 0
        self.height = 0
        self._level = level
        self._text  = text

    def draw(self) -> None:  # nothing to render
        pass

    def getPlainText(self) -> str:
        return self._text


class _RiskGaugeBar(Flowable):
    """Horizontal coloured gauge bar visualising a 0-100 risk score."""

    _ZONES = [
        (0,  20,  "#22c55e"),   # Low     – green
        (20, 40,  "#eab308"),   # Medium  – yellow
        (40, 70,  "#f97316"),   # High    – orange
        (70, 100, "#ef4444"),   # Critical – red
    ]
    _LABELS = [("LOW", 10), ("MEDIUM", 30), ("HIGH", 55), ("CRITICAL", 85)]

    def __init__(self, score: int, width: float, height: float = 24.0) -> None:
        Flowable.__init__(self)
        self.score  = max(0, min(100, score))
        self.width  = width
        self.height = height

    def _score_color(self) -> "colors.Color":
        for z_start, z_end, z_hex in self._ZONES:
            if self.score <= z_end:
                return colors.HexColor(z_hex)
        return colors.HexColor("#ef4444")

    def draw(self) -> None:
        from reportlab.lib.colors import Color as _RLColor
        c = self.canv
        c.saveState()
        w, h  = self.width, self.height
        bar_h = h * 0.30
        bar_y = h * 0.46

        # Grey background track
        c.setFillColor(C_BORDER)
        c.rect(0, bar_y, w, bar_h, fill=1, stroke=0)

        # Subtle zone tint bands
        for z_start, z_end, z_hex in self._ZONES:
            rgb = colors.HexColor(z_hex)
            c.setFillColor(_RLColor(rgb.red, rgb.green, rgb.blue, alpha=0.18))
            x1 = z_start / 100 * w
            c.rect(x1, bar_y, (z_end - z_start) / 100 * w, bar_h, fill=1, stroke=0)

        # Zone dividers (white lines)
        c.setStrokeColor(C_WHITE)
        c.setLineWidth(0.7)
        for z_start, _, _ in self._ZONES[1:]:
            x = z_start / 100 * w
            c.line(x, bar_y, x, bar_y + bar_h)

        # Filled progress segment
        fill_w = self.score / 100 * w
        if fill_w > 0:
            c.setFillColor(self._score_color())
            c.rect(0, bar_y, fill_w, bar_h, fill=1, stroke=0)
            c.setStrokeColor(C_WHITE)
            c.setLineWidth(1.2)
            c.line(fill_w, bar_y - 1, fill_w, bar_y + bar_h + 1)

        # Zone labels below track
        c.setFont("Helvetica", 5.5)
        c.setFillColor(C_GREY)
        for label, pct in self._LABELS:
            c.drawCentredString(pct / 100 * w, bar_y - 8, label)

        # Score marker pip above track
        pip_r = bar_h * 0.48
        c.setFillColor(self._score_color())
        c.setStrokeColor(C_WHITE)
        c.setLineWidth(1.0)
        c.circle(fill_w if fill_w > 0 else 0, bar_y + bar_h + pip_r * 0.6, pip_r, fill=1, stroke=1)

        c.restoreState()


class _WorldMapFlowable(Flowable):
    """A custom Flowable that renders a modern world map with region markers."""

    def __init__(
        self,
        width: float,
        height: float,
        regions: list[tuple[str, str, str | None]],
    ) -> None:
        Flowable.__init__(self)
        self.width   = width
        self.height  = height
        self.regions = regions
        self._img_reader: "ImageReader | None" = self._prerender()

    def _prerender(self) -> "ImageReader | None":
        buf = _render_world_map_pil(self.width, self.height, self.regions)
        if buf is None:
            return None
        return ImageReader(buf)

    # ── ReportLab projection helper (y=0 at bottom) ────────────────────────
    def _proj(self, lon: float, lat: float) -> tuple[float, float]:
        x = (lon - _MAP_LON_MIN) / (_MAP_LON_MAX - _MAP_LON_MIN) * self.width
        y = (lat - _MAP_LAT_MIN) / (_MAP_LAT_MAX - _MAP_LAT_MIN) * self.height
        return x, y

    def draw(self) -> None:
        c = self.canv
        c.saveState()

        if self._img_reader is not None:
            # PIL-rendered image path (high quality)
            c.drawImage(
                self._img_reader, 0, 0, self.width, self.height,
                preserveAspectRatio=False, mask="auto",
            )
        else:
            # ── ReportLab fallback (PIL unavailable) ───────────────────────
            c.setFillColor(_MAP_OCEAN)
            c.rect(0, 0, self.width, self.height, fill=1, stroke=0)

            c.setStrokeColor(_MAP_GRID)
            c.setLineWidth(0.3)
            for lon in range(-150, 151, 30):
                x, _ = self._proj(lon, 0)
                c.line(x, 0, x, self.height)
            for lat in range(-60, 61, 30):
                _, y = self._proj(0, lat)
                c.line(0, y, self.width, y)

            c.setFillColor(_MAP_LAND)
            c.setStrokeColor(_MAP_BORDER)
            c.setLineWidth(0.5)
            for poly in _CONTINENT_POLYS:
                if len(poly) < 3:
                    continue
                path = c.beginPath()
                x0, y0 = self._proj(*poly[0])
                path.moveTo(x0, y0)
                for lon, lat in poly[1:]:
                    path.lineTo(*self._proj(lon, lat))
                path.close()
                c.drawPath(path, fill=1, stroke=1)

            c.setStrokeColor(_MAP_OUTLINE)
            c.setLineWidth(1.0)
            c.rect(0, 0, self.width, self.height, fill=0, stroke=1)

            dot_r = min(3.5, self.height * 0.045)
            seen_pts: set[tuple[str, str]] = set()
            for region_name, provider in self.regions:
                key = (region_name.strip().lower(), provider.lower())
                if key in seen_pts:
                    continue
                seen_pts.add(key)
                coords = _REGION_COORDS.get(region_name.strip().lower())
                if not coords:
                    continue
                lat, lon = coords
                if lat < _MAP_LAT_MIN or lat > _MAP_LAT_MAX:
                    continue
                x, y = self._proj(lon, lat)
                prov_color = _PROVIDER_DOT_COLORS.get(provider.lower(), C_GREY)
                c.setFillColor(C_WHITE)
                c.setLineWidth(0)
                c.circle(x, y, dot_r + 1.8, fill=1, stroke=0)
                c.setFillColor(prov_color)
                c.setStrokeColor(C_WHITE)
                c.setLineWidth(0.8)
                c.circle(x, y, dot_r, fill=1, stroke=1)

        c.restoreState()


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = dict(
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=C_DARK,
    )
    return {
        "h1": ParagraphStyle("h1", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 26,
            "leading": 32, "textColor": C_NAVY, "spaceAfter": 8}),
        "h2": ParagraphStyle("h2", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 16,
            "leading": 20, "textColor": C_NAVY, "spaceBefore": 18, "spaceAfter": 6}),
        "h3": ParagraphStyle("h3", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 12,
            "leading": 16, "textColor": C_DARK, "spaceBefore": 10, "spaceAfter": 4}),
        "body": ParagraphStyle("body", **{**base, "spaceAfter": 4}),
        "body_sm": ParagraphStyle("body_sm", **{**base, "fontSize": 9, "leading": 12}),
        "muted": ParagraphStyle("muted", **{**base,
            "fontSize": 9, "leading": 12, "textColor": C_GREY}),
        "code": ParagraphStyle("code", **{**base,
            "fontName": "Courier", "fontSize": 8, "leading": 11,
            "textColor": C_DARK, "backColor": C_GREY_LT,
            "borderPadding": (3, 5, 3, 5)}),
        "cover_sub": ParagraphStyle("cover_sub", **{**base,
            "fontSize": 14, "leading": 18, "textColor": C_GREY}),
        "cover_meta": ParagraphStyle("cover_meta", **{**base,
            "fontSize": 11, "leading": 16, "textColor": C_DARK}),
        "center": ParagraphStyle("center", **{**base, "alignment": TA_CENTER}),
        "right": ParagraphStyle("right", **{**base, "alignment": TA_RIGHT}),
        "pill_pass": ParagraphStyle("pill_pass", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9,
            "textColor": C_GREEN, "alignment": TA_CENTER}),
        "pill_fail": ParagraphStyle("pill_fail", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9,
            "textColor": C_RED, "alignment": TA_CENTER}),
        "pill_skip": ParagraphStyle("pill_skip", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9,
            "textColor": C_GREY, "alignment": TA_CENTER}),
        "sev_critical": ParagraphStyle("sev_critical", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_RED, "alignment": TA_CENTER}),
        "sev_high": ParagraphStyle("sev_high", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_ORANGE, "alignment": TA_CENTER}),
        "sev_medium": ParagraphStyle("sev_medium", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_YELLOW, "alignment": TA_CENTER}),
        "sev_low": ParagraphStyle("sev_low", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_BLUE, "alignment": TA_CENTER}),
        "tbl_header": ParagraphStyle("tbl_header", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "leading": 11, "textColor": C_WHITE, "alignment": TA_CENTER}),
        "tbl_header_left": ParagraphStyle("tbl_header_left", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "leading": 11, "textColor": C_WHITE}),
        "kpi_number": ParagraphStyle("kpi_number", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 22,
            "leading": 26, "textColor": C_WHITE, "alignment": TA_CENTER}),
        "kpi_label": ParagraphStyle("kpi_label", **{**base,
            "fontSize": 8, "leading": 11, "textColor": C_WHITE, "alignment": TA_CENTER}),
        "alert_text": ParagraphStyle("alert_text", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9, "leading": 12,
            "textColor": C_ORANGE}),
    }


# ── Logo drawing helpers ──────────────────────────────────────────────────────

def _draw_logo(c: pdfcanvas.Canvas, x: float, y: float, size: float = 28) -> None:
    """Draw the WAF++ logo image at (x, y) with given size (square)."""
    c.saveState()
    if _LOGO_IMG is not None:
        c.drawImage(_LOGO_IMG, x, y, width=size, height=size, mask="auto")
    else:
        # Minimal fallback: dark square with "W"
        c.setFillColor(C_NAVY)
        c.rect(x, y, size, size, fill=1, stroke=0)
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", size * 0.55)
        c.drawCentredString(x + size / 2, y + size * 0.2, "W")
    c.restoreState()


def _draw_wordmark(c: pdfcanvas.Canvas, x: float, y: float, size: float = 28) -> None:
    """Draw logo image + 'WAF++' text wordmark."""
    _draw_logo(c, x, y, size)
    text_x = x + size + 5
    text_y = y + size * 0.24
    font_size = size * 0.52
    c.saveState()
    c.setFillColor(C_NAVY)
    c.setFont("Helvetica-Bold", font_size)
    c.drawString(text_x, text_y, "WAF")
    w_waf = c.stringWidth("WAF", "Helvetica-Bold", font_size)
    c.setFillColor(C_BLUE)
    c.drawString(text_x + w_waf, text_y, "++")
    c.restoreState()


# ── Page templates ─────────────────────────────────────────────────────────────

class _CoverCanvas:
    """Mixin applied during cover page rendering."""

    def __init__(self, generated_at: str):
        self.generated_at = generated_at

    def __call__(self, canvas: pdfcanvas.Canvas, doc: BaseDocTemplate) -> None:
        canvas.saveState()
        # Full navy background header band
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, PAGE_H - 8 * cm, PAGE_W, 8 * cm, fill=1, stroke=0)

        # Blue accent bar at very top
        canvas.setFillColor(C_BLUE)
        canvas.rect(0, PAGE_H - 4 * mm, PAGE_W, 4 * mm, fill=1, stroke=0)

        # Large logo in header
        _draw_logo(canvas, MARGIN, PAGE_H - 5.5 * cm, size=52)

        # "WAF++" in header
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 28)
        canvas.drawString(MARGIN + 62, PAGE_H - 3.8 * cm, "WAF")
        w = canvas.stringWidth("WAF", "Helvetica-Bold", 28)
        canvas.setFillColor(C_BLUE)
        canvas.drawString(MARGIN + 62 + w, PAGE_H - 3.8 * cm, "++")

        canvas.setFillColor(C_GREY_LT)
        canvas.setFont("Helvetica", 11)
        canvas.drawString(MARGIN + 62, PAGE_H - 5.1 * cm, "Architecture Review Report")

        # Bottom footer bar
        canvas.setFillColor(C_GREY_LT)
        canvas.rect(0, 0, PAGE_W, 1.8 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(MARGIN, 0.65 * cm, f"Generated  {self.generated_at}  ·  WAF++ PASS v{__version__}")
        canvas.drawRightString(PAGE_W - MARGIN, 0.65 * cm, "waf2p.dev")
        canvas.restoreState()


class _PageCanvas:
    """Header/footer applied to all non-cover pages."""

    def __init__(self, generated_at: str):
        self.generated_at = generated_at

    def __call__(self, canvas: pdfcanvas.Canvas, doc: BaseDocTemplate) -> None:
        canvas.saveState()
        page_num = doc.page

        # Header line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, PAGE_H - MARGIN + 4 * mm, PAGE_W - MARGIN, PAGE_H - MARGIN + 4 * mm)

        # Wordmark (small) top-left
        _draw_wordmark(canvas, MARGIN, PAGE_H - MARGIN + 5 * mm, size=16)

        # Report title top-right
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN + 8 * mm,
                               "Architecture Review Report")

        # Footer line
        canvas.line(MARGIN, MARGIN - 4 * mm, PAGE_W - MARGIN, MARGIN - 4 * mm)

        # Footer left: date
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C_GREY)
        canvas.drawString(MARGIN, MARGIN - 9 * mm,
                          f"WAF++ PASS v{__version__}  ·  {self.generated_at}")

        # Footer right: page number
        canvas.drawRightString(PAGE_W - MARGIN, MARGIN - 9 * mm, f"Page {page_num}")

        canvas.restoreState()


# ── Flowable helpers ──────────────────────────────────────────────────────────

def _hr(color=C_BORDER, thickness=0.5) -> HRFlowable:
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6)


def _status_pill(status: str, S: dict) -> Paragraph:
    icon = STATUS_ICON.get(status, "?")
    style_key = {"PASS": "pill_pass", "FAIL": "pill_fail", "SKIP": "pill_skip", "WAIVED": "pill_skip"}.get(status, "body_sm")
    return Paragraph(f"{icon} {status}", S[style_key])


def _severity_para(severity: str, S: dict) -> Paragraph:
    style_key = f"sev_{severity.lower()}"
    if style_key not in S:
        style_key = "body_sm"
    return Paragraph(severity.upper(), S[style_key])


def _section_header(title: str, S: dict, toc_level: int | None = 1) -> list:
    """Blue left-bordered section header. Auto-registers a TOC entry unless toc_level is None."""
    entries: list = []
    if toc_level is not None:
        entries.append(_TOCEntry(toc_level, title))
    entries += [
        Spacer(1, 4 * mm),
        Table(
            [[Paragraph(title, S["h2"])]],
            colWidths=[CONTENT_W],
            style=TableStyle([
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBEFORE",    (0, 0), (0, 0), 3, C_BLUE),
                ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_LT),
            ]),
        ),
        Spacer(1, 3 * mm),
    ]
    return entries


# ── Cover page content ────────────────────────────────────────────────────────

def _cover_content(report: Report, S: dict, generated_at: str) -> list:
    """Flowables for the cover page body (below the drawn header band)."""
    elems = [
        Spacer(1, 9 * cm),  # clear the drawn header
        Paragraph("Architecture Review Report", S["h1"]),
        Paragraph("Infrastructure Security &amp; Compliance Assessment", S["cover_sub"]),
        Spacer(1, 1 * cm),
        _hr(C_BLUE, 1.5),
        Spacer(1, 6 * mm),
    ]

    meta = [
        ["Checked path",     str(report.path)],
        ["Report date",      generated_at],
        ["Controls loaded",  str(report.controls_loaded)],
        ["Controls run",     str(report.controls_run)],
        ["Tool version",     f"WAF++ PASS v{__version__}"],
    ]
    meta_table = Table(
        [[Paragraph(k, S["muted"]), Paragraph(v, S["body"])] for k, v in meta],
        colWidths=[4 * cm, CONTENT_W - 4 * cm],
        style=TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.4, C_BORDER),
        ]),
    )
    elems.append(meta_table)
    elems.append(Spacer(1, 1.5 * cm))

    # Quick-stat boxes: PASS / FAIL / SKIP / WAIVED
    stats = [
        (f"{report.total_pass}",   "PASS",   C_GREEN,  C_GREEN_LT),
        (f"{report.total_fail}",   "FAIL",   C_RED,    C_RED_LT),
        (f"{report.total_skip}",   "SKIP",   C_GREY,   C_GREY_LT),
        (f"{report.total_waived}", "WAIVED", C_PURPLE, C_PURPLE_LT),
    ]
    stat_cells = []
    for val, label, fg, bg in stats:
        cell = Table(
            [[Paragraph(val,   ParagraphStyle("sv", fontName="Helvetica-Bold",
                                              fontSize=32, leading=36, textColor=fg,
                                              alignment=TA_CENTER))],
             [Paragraph(label, ParagraphStyle("sl", fontName="Helvetica-Bold",
                                              fontSize=10, leading=14, textColor=fg,
                                              alignment=TA_CENTER))]],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("ROUNDEDCORNERS", (0, 0), (-1, -1), 6),
            ]),
        )
        stat_cells.append(cell)

    box_w = (CONTENT_W - 3 * 0.5 * cm) / 4
    stat_row = Table(
        [stat_cells],
        colWidths=[box_w, box_w, box_w, box_w],
        style=TableStyle([
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]),
    )
    elems.append(stat_row)
    return elems


# ── Executive Summary ─────────────────────────────────────────────────────────

def _executive_summary(report: Report, S: dict) -> list:
    elems = [*_section_header("Executive Summary", S)]

    total_checks = report.check_pass + report.check_fail + report.check_skip

    # Two-column stats
    left = [
        ["Metric", "Controls", "Checks"],
        ["✓ Passed",
         str(report.total_pass),
         str(report.check_pass)],
        ["✗ Failed",
         str(report.total_fail),
         str(report.check_fail)],
        ["─ Skipped",
         str(report.total_skip),
         str(report.check_skip)],
        ["○ Waived",
         str(report.total_waived),
         "—"],
        ["Total",
         str(report.controls_run),
         str(total_checks)],
    ]
    row_colors = [C_GREY_LT, C_GREEN_LT, C_RED_LT, C_YELLOW_LT, C_PURPLE_LT, C_BLUE_LT]
    col_w = [CONTENT_W * 0.45, CONTENT_W * 0.275, CONTENT_W * 0.275]

    ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("LEADING",       (0, 0), (-1, -1), 14),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("FONTNAME",      (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND",    (0, -1), (-1, -1), C_BLUE_LT),
    ])
    for i, bg in enumerate(row_colors):
        ts.add("BACKGROUND", (0, i), (-1, i), bg)

    elems.append(Table([[Paragraph(str(v), S["body_sm"]) for v in row]
                         for row in left],
                        colWidths=col_w, style=ts))
    elems.append(Spacer(1, 5 * mm))

    # Pillar/severity breakdown
    pillars: dict[str, dict] = {}
    for cr in report.results:
        p = cr.control.pillar.capitalize()
        if p not in pillars:
            pillars[p] = {"PASS": 0, "FAIL": 0, "SKIP": 0, "WAIVED": 0}
        pillars[p][cr.status] = pillars[p].get(cr.status, 0) + 1

    if pillars:
        elems += _section_header("Pillar Breakdown", S)
        pill_rows = [["Pillar", "✓ Pass", "✗ Fail", "─ Skip", "○ Waived"]]
        for pname, cnts in sorted(pillars.items()):
            pill_rows.append([
                pname,
                str(cnts.get("PASS", 0)),
                str(cnts.get("FAIL", 0)),
                str(cnts.get("SKIP", 0)),
                str(cnts.get("WAIVED", 0)),
            ])

        pts = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("LEADING",       (0, 0), (-1, -1), 13),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_GREY_LT),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ])
        col_w2 = [CONTENT_W * 0.32, CONTENT_W * 0.17, CONTENT_W * 0.17, CONTENT_W * 0.17, CONTENT_W * 0.17]
        elems.append(Table([[Paragraph(str(v), S["body_sm"]) for v in row]
                             for row in pill_rows],
                            colWidths=col_w2, style=pts))

    return elems


# ── Controls overview table ───────────────────────────────────────────────────

def _controls_overview(report: Report, S: dict) -> list:
    elems = [*_section_header("Controls Overview", S),
             Paragraph(
                 "All evaluated controls with their overall result. "
                 "Detailed findings for failed controls follow in the next section.",
                 S["muted"]),
             Spacer(1, 4 * mm)]

    header = ["ID", "Title", "Pillar", "Severity", "Status",
              "✓", "✗", "─"]
    rows = [header]
    for cr in report.results:
        c = cr.control
        rows.append([
            c.id,
            c.title[:42] + ("…" if len(c.title) > 42 else ""),
            c.pillar.capitalize(),
            c.severity.upper(),
            cr.status,
            str(sum(1 for r in cr.results if r.status == "PASS")),
            str(sum(1 for r in cr.results if r.status == "FAIL")),
            str(sum(1 for r in cr.results if r.status == "SKIP")),
        ])

    col_w = [2.4*cm, 6.2*cm, 1.8*cm, 1.6*cm, 1.4*cm, 0.7*cm, 0.7*cm, 0.7*cm]

    ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("ALIGN",         (3, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
    ])
    # Color status and severity cells per row
    for i, cr in enumerate(report.results, start=1):
        sev = cr.control.severity.lower()
        sev_fg, sev_bg = SEVERITY_COLORS.get(sev, (C_GREY, C_GREY_LT))
        ts.add("BACKGROUND", (3, i), (3, i), sev_bg)
        ts.add("TEXTCOLOR",  (3, i), (3, i), sev_fg)
        ts.add("FONTNAME",   (3, i), (3, i), "Helvetica-Bold")

        st = cr.status
        st_fg, st_bg = STATUS_COLORS.get(st, (C_GREY, C_GREY_LT))
        ts.add("BACKGROUND", (4, i), (4, i), st_bg)
        ts.add("TEXTCOLOR",  (4, i), (4, i), st_fg)
        ts.add("FONTNAME",   (4, i), (4, i), "Helvetica-Bold")

    # Convert to Paragraph cells for wrapping (header row gets white text)
    para_rows = []
    for i, row in enumerate(rows):
        if i == 0:
            para_rows.append([
                Paragraph(str(cell), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                for j, cell in enumerate(row)
            ])
        else:
            para_rows.append([Paragraph(str(cell), S["body_sm"]) for cell in row])

    elems.append(Table(para_rows, colWidths=col_w, style=ts))
    return elems


# ── Findings detail ───────────────────────────────────────────────────────────

def _findings_section(report: Report, S: dict) -> list:
    failing = [cr for cr in report.results if cr.status == "FAIL"]
    if not failing:
        elems = [*_section_header("Findings", S),
                 Paragraph("✓  No failures detected. All evaluated controls passed.", S["body"])]
        return elems

    elems = [*_section_header("Findings", S),
             Paragraph(
                 f"{len(failing)} control(s) produced findings that require attention. "
                 "Each finding includes the affected resource, the specific violation, "
                 "and remediation guidance.",
                 S["muted"]),
             Spacer(1, 4 * mm)]

    for cr in failing:
        c = cr.control
        sev_fg, sev_bg = SEVERITY_COLORS.get(c.severity.lower(), (C_GREY, C_GREY_LT))

        # Control header bar
        header_content = [
            [
                Paragraph(
                    f'<font name="Helvetica-Bold" size="11">{c.id}</font>'
                    f'  <font color="#{_hex(C_GREY)}" size="9">{c.title}</font>',
                    S["body"]),
                Paragraph(
                    f'<font name="Helvetica-Bold">{c.severity.upper()}</font>',
                    ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=8,
                                   textColor=sev_fg, alignment=TA_CENTER)),
            ]
        ]
        header_table = Table(
            header_content,
            colWidths=[CONTENT_W - 2 * cm, 2 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
                ("BACKGROUND",    (1, 0), (1, 0),   sev_bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (0, 0),   10),
                ("RIGHTPADDING",  (-1, 0), (-1, 0), 8),
                ("LINEBEFORE",    (0, 0), (0, 0),   3, sev_fg),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )

        # Description
        desc_para = Paragraph(
            (c.description or "").strip().replace("\n", " ")[:350] + (
                "…" if len((c.description or "")) > 350 else ""),
            S["muted"])

        # Individual check result rows
        check_rows = []
        for r in cr.results:
            if r.status != "FAIL":
                continue
            st_fg, st_bg = STATUS_COLORS.get(r.status, (C_GREY, C_GREY_LT))
            check_rows.append([
                Paragraph(f'<font name="Helvetica-Bold">{r.status}</font>', ParagraphStyle(
                    "cs", fontName="Helvetica-Bold", fontSize=8,
                    textColor=st_fg, alignment=TA_CENTER)),
                Paragraph(f'<font name="Courier" size="8">{r.resource}</font>', S["body_sm"]),
                Paragraph(r.message or "", S["body_sm"]),
            ])

        if check_rows:
            check_ts = TableStyle([
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("LEADING",       (0, 0), (-1, -1), 11),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
                ("BACKGROUND",    (0, 0), (-1, -1), C_RED_LT),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ])
            check_table = Table(
                check_rows,
                colWidths=[1.3 * cm, 4.5 * cm, CONTENT_W - 5.8 * cm],
                style=check_ts,
            )
        else:
            check_table = None

        # Remediation box (first failing check's remediation)
        rem_text = next(
            (r.remediation for r in cr.results if r.status == "FAIL" and r.remediation), None
        )
        rem_block = None
        if rem_text:
            rem_para = Paragraph(
                "→ <b>Remediation:</b> " + rem_text.strip().replace("\n", " "),
                S["body_sm"])
            rem_block = Table(
                [[rem_para]],
                colWidths=[CONTENT_W],
                style=TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), C_BLUE_LT),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                    ("TOPPADDING",    (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBEFORE",    (0, 0), (0, 0),   3, C_BLUE),
                ]),
            )

        block_items = [header_table, Spacer(1, 2 * mm), desc_para, Spacer(1, 2 * mm)]
        if check_table:
            block_items.append(check_table)
        if rem_block:
            block_items += [Spacer(1, 2 * mm), rem_block]
        block_items.append(Spacer(1, 6 * mm))

        elems.append(KeepTogether(block_items[:4]))  # header + desc always together
        if check_table:
            elems.append(check_table)
        if rem_block:
            elems += [Spacer(1, 2 * mm), rem_block]
        elems.append(Spacer(1, 6 * mm))

    return elems


# ── Passed controls appendix ──────────────────────────────────────────────────

def _passed_section(report: Report, S: dict) -> list:
    passed  = [cr for cr in report.results if cr.status == "PASS"]
    skipped = [cr for cr in report.results if cr.status == "SKIP"]
    waived  = [cr for cr in report.results if cr.status == "WAIVED"]
    elems = [*_section_header("Passed Controls", S)]

    if passed:
        rows = [["Control ID", "Title", "Checks passed"]]
        for cr in passed:
            rows.append([
                cr.control.id,
                cr.control.title[:55] + ("…" if len(cr.control.title) > 55 else ""),
                str(sum(1 for r in cr.results if r.status == "PASS")),
            ])
        ts = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_GREEN),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREEN_LT]),
        ])
        col_w = [2.8 * cm, CONTENT_W - 5.8 * cm, 3 * cm]
        elems.append(Table(
            [
                [Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                 for j, v in enumerate(row)]
                if i == 0 else
                [Paragraph(str(v), S["body_sm"]) for v in row]
                for i, row in enumerate(rows)
            ],
            colWidths=col_w, style=ts))
    else:
        elems.append(Paragraph("No controls passed in this run.", S["muted"]))

    if skipped:
        elems += [Spacer(1, 5 * mm), *_section_header("Skipped Controls", S),
                  Paragraph(
                      "The following controls were skipped — either no matching Terraform "
                      "resources were found, or all assertions use operators not supported "
                      "in automated evaluation.",
                      S["muted"]),
                  Spacer(1, 3 * mm)]
        skip_rows = [["Control ID", "Title", "Reason"]]
        for cr in skipped:
            first_skip = next(
                (r.message for r in cr.results if r.status == "SKIP"),
                "No matching resources found.")
            skip_rows.append([cr.control.id,
                               cr.control.title[:45] + ("…" if len(cr.control.title) > 45 else ""),
                               first_skip[:80]])
        ts2 = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_GREY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ])
        col_w2 = [2.8 * cm, CONTENT_W * 0.4, CONTENT_W - 2.8 * cm - CONTENT_W * 0.4]
        elems.append(Table(
            [
                [Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                 for j, v in enumerate(row)]
                if i == 0 else
                [Paragraph(str(v), S["body_sm"]) for v in row]
                for i, row in enumerate(skip_rows)
            ],
            colWidths=col_w2, style=ts2))

    if waived:
        elems += [Spacer(1, 5 * mm), *_section_header("Waived Controls", S),
                  Paragraph(
                      "The following controls have been intentionally waived by the team. "
                      "Each waiver includes the justification recorded at the time of acceptance. "
                      "Waived controls do not contribute to the risk score or exit code.",
                      S["muted"]),
                  Spacer(1, 3 * mm)]
        waive_rows = [["Control ID", "Title", "Waiver Reason"]]
        for cr in waived:
            waive_rows.append([
                cr.control.id,
                cr.control.title[:45] + ("…" if len(cr.control.title) > 45 else ""),
                (cr.waived_reason or "")[:80],
            ])
        ts3 = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PURPLE),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_PURPLE_LT]),
        ])
        col_w3 = [2.8 * cm, CONTENT_W * 0.4, CONTENT_W - 2.8 * cm - CONTENT_W * 0.4]
        elems.append(Table(
            [
                [Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                 for j, v in enumerate(row)]
                if i == 0 else
                [Paragraph(str(v), S["body_sm"]) for v in row]
                for i, row in enumerate(waive_rows)
            ],
            colWidths=col_w3, style=ts3))

    return elems


# ── Regulatory Alignment section ─────────────────────────────────────────────

def _build_framework_map(report: Report) -> dict[str, dict]:
    """Aggregate per-framework data from all control results.

    Returns dict keyed by framework name:
        {"items": [ControlResult, ...], "PASS": int, "FAIL": int, "SKIP": int}
    """
    frameworks: dict[str, dict] = {}
    for cr in report.results:
        for reg in cr.control.regulatory_mapping:
            fname = reg.get("framework", "").strip()
            if not fname:
                continue
            if fname not in frameworks:
                frameworks[fname] = {"items": [], "PASS": 0, "FAIL": 0, "SKIP": 0, "WAIVED": 0}
            frameworks[fname]["items"].append(cr)
            frameworks[fname][cr.status] = frameworks[fname].get(cr.status, 0) + 1
    return frameworks


# Priority order for the 6 frameworks shown in the PDF cards.
# Only frameworks whose name matches one of these (case-insensitive prefix) will be shown.
_PRIORITY_FRAMEWORKS: list[str] = [
    "GDPR",
    "BSI C5:2020",
    "BSI C3A:2026",
    "ISO 27001:2022",
    "EUCS (ENISA)",
    "SOC 2",
    "AWS Well-Architected Framework",
]


def _reg_framework_card(
    framework: str,
    data: dict,
    card_w: float,
    badge_color: colors.Color,
) -> Table:
    """Build a single regulatory framework card as a flat 3-column Table.

    Layout (3 equal columns, all rows span all cols except the stats row):
        Row 0 – header band: initials badge | framework name  (spans all 3)
        Row 1 – stats:        ✓ PASS  |  ✗ FAIL  |  ─ SKIP
        Row 2 – control IDs  (spans all 3)
    """
    col = card_w / 3  # each of the 3 equal columns

    initials = "".join(w[0].upper() for w in framework.split() if w)[:3]
    display_name = framework if len(framework) <= 30 else framework[:28] + "…"

    # Deduplicate control IDs, keeping first occurrence order
    seen_ids: set[str] = set()
    unique_crs = []
    for cr in data["items"]:
        if cr.control.id not in seen_ids:
            seen_ids.add(cr.control.id)
            unique_crs.append(cr)

    # Row 0 – header
    header_para = Paragraph(
        f'<font name="Helvetica-Bold" size="13" color="white">{initials}</font>'
        f'<font name="Helvetica" size="8" color="white">  {display_name}</font>',
        ParagraphStyle("ch", leading=16, alignment=TA_LEFT),
    )

    # Row 1 – stat cells (one per column, no span)
    def _stat_para(icon: str, count: int, fg: colors.Color) -> Paragraph:
        return Paragraph(
            f'<font name="Helvetica-Bold" size="9" color="#{_hex(fg)}">{icon} {count}</font>',
            ParagraphStyle("sp", leading=13, alignment=TA_CENTER),
        )

    pass_p = _stat_para("✓", data["PASS"], C_GREEN)
    fail_p = _stat_para("✗", data["FAIL"], C_RED)
    skip_p = _stat_para("─", data["SKIP"], C_GREY)

    # Row 2 – control IDs
    id_fragments = []
    for cr in unique_crs:
        st_fg = {"PASS": C_GREEN, "FAIL": C_RED, "SKIP": C_GREY}.get(cr.status, C_GREY)
        icon = STATUS_ICON.get(cr.status, "?")
        id_fragments.append(
            f'<font name="Courier" size="7" color="#{_hex(C_DARK)}">{cr.control.id}</font>'
            f'<font name="Helvetica" size="7" color="#{_hex(st_fg)}"> {icon}</font>'
        )
    ids_para = Paragraph(
        "  ·  ".join(id_fragments) if id_fragments else "—",
        ParagraphStyle("ci", leading=11, textColor=C_DARK),
    )

    # Logo image overrides initials in header if available
    logo_img = _reg_logo(framework)
    if logo_img is not None:
        from reportlab.platypus import Image as RLImage
        logo_size = 28.0
        header_para = Paragraph(
            f'<font name="Helvetica-Bold" size="9" color="white">  {display_name}</font>',
            ParagraphStyle("ch2", leading=14, alignment=TA_LEFT),
        )
        # We can't mix Image + Paragraph in a spanned cell simply, so fall back to
        # showing the initials alongside the name (logo dropped to avoid ReportLab
        # nested-image-in-span issues — place logo via background or separate row).
        header_para = Paragraph(
            f'<font name="Helvetica-Bold" size="13" color="white">{initials}</font>'
            f'<font name="Helvetica" size="8" color="white">  {display_name}</font>',
            ParagraphStyle("ch3", leading=16, alignment=TA_LEFT),
        )

    rows = [
        [header_para, "", ""],        # row 0 – header (will be spanned)
        [pass_p, fail_p, skip_p],     # row 1 – stats
        [ids_para, "", ""],           # row 2 – control IDs (will be spanned)
    ]

    ts = TableStyle([
        # Spans
        ("SPAN",          (0, 0), (2, 0)),
        ("SPAN",          (0, 2), (2, 2)),

        # Header band
        ("BACKGROUND",    (0, 0), (2, 0),  badge_color),
        ("TOPPADDING",    (0, 0), (2, 0),  10),
        ("BOTTOMPADDING", (0, 0), (2, 0),  10),
        ("LEFTPADDING",   (0, 0), (2, 0),  10),
        ("RIGHTPADDING",  (0, 0), (2, 0),  8),
        ("VALIGN",        (0, 0), (2, 0),  "MIDDLE"),

        # Stats row
        ("BACKGROUND",    (0, 1), (0, 1),  C_GREEN_LT),
        ("BACKGROUND",    (1, 1), (1, 1),  C_RED_LT),
        ("BACKGROUND",    (2, 1), (2, 1),  C_GREY_LT),
        ("TOPPADDING",    (0, 1), (2, 1),  6),
        ("BOTTOMPADDING", (0, 1), (2, 1),  6),
        ("LEFTPADDING",   (0, 1), (2, 1),  4),
        ("RIGHTPADDING",  (0, 1), (2, 1),  4),
        ("VALIGN",        (0, 1), (2, 1),  "MIDDLE"),
        ("LINEBELOW",     (0, 1), (2, 1),  0.4, C_BORDER),
        ("LINEABOVE",     (0, 1), (2, 1),  0.4, C_BORDER),

        # Controls row
        ("BACKGROUND",    (0, 2), (2, 2),  C_WHITE),
        ("TOPPADDING",    (0, 2), (2, 2),  7),
        ("BOTTOMPADDING", (0, 2), (2, 2),  8),
        ("LEFTPADDING",   (0, 2), (2, 2),  8),
        ("RIGHTPADDING",  (0, 2), (2, 2),  8),
        ("VALIGN",        (0, 2), (2, 2),  "TOP"),

        # Outer border in badge color
        ("BOX",           (0, 0), (-1, -1), 1.2, badge_color),
    ])

    return Table(rows, colWidths=[col, col, col], style=ts)


def _regulatory_alignment(report: Report, S: dict) -> list:
    """Build the Regulatory Alignment section flowables."""
    all_frameworks = _build_framework_map(report)
    if not all_frameworks:
        return []

    # Filter to priority frameworks only (max 6), in defined order
    frameworks: dict[str, dict] = {}
    for priority_name in _PRIORITY_FRAMEWORKS:
        # Match by exact name or case-insensitive prefix
        for fname, data in all_frameworks.items():
            if fname.lower().startswith(priority_name.lower()):
                if fname not in frameworks:
                    frameworks[fname] = data
                break
        if len(frameworks) == 6:
            break

    if not frameworks:
        return []

    elems: list = [
        *_section_header("Regulatory Alignment", S),
        Paragraph(
            "Overview of how WAF++ controls map to the key regulatory and industry frameworks. "
            "Each card shows the compliance posture (PASS / FAIL / SKIP) for all controls "
            "that reference the framework.",
            S["muted"]),
        Spacer(1, 5 * mm),
    ]

    # ── Summary table ─────────────────────────────────────────────────────────
    summary_rows = [["Framework", "Mapped Controls", "✓ Pass", "✗ Fail", "─ Skip", "○ Waived"]]
    for fname, d in frameworks.items():
        total = d["PASS"] + d["FAIL"] + d["SKIP"] + d.get("WAIVED", 0)
        summary_rows.append([fname, str(total), str(d["PASS"]), str(d["FAIL"]), str(d["SKIP"]), str(d.get("WAIVED", 0))])

    sum_ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
    ])
    for i, (fname, d) in enumerate(frameworks.items(), start=1):
        if d["FAIL"] > 0:
            sum_ts.add("TEXTCOLOR", (3, i), (3, i), C_RED)
            sum_ts.add("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")
        if d["PASS"] > 0:
            sum_ts.add("TEXTCOLOR", (2, i), (2, i), C_GREEN)
            sum_ts.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")
        if d.get("WAIVED", 0) > 0:
            sum_ts.add("TEXTCOLOR", (5, i), (5, i), C_PURPLE)
            sum_ts.add("FONTNAME",  (5, i), (5, i), "Helvetica-Bold")

    sum_col_w = [CONTENT_W * 0.34, CONTENT_W * 0.14, CONTENT_W * 0.13,
                 CONTENT_W * 0.13, CONTENT_W * 0.13, CONTENT_W * 0.13]
    elems.append(Table(
        [[Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
          for j, v in enumerate(row)]
         if i == 0 else
         [Paragraph(str(v), S["body_sm"]) for v in row]
         for i, row in enumerate(summary_rows)],
        colWidths=sum_col_w, style=sum_ts))

    elems.append(Spacer(1, 8 * mm))
    elems += _section_header("Framework Cards", S)
    elems.append(Paragraph(
        "Each card shows the framework initials, PASS / FAIL / SKIP counts, "
        "and the WAF++ control IDs that reference it.  "
        "Drop a logo PNG into <code>assets/regulatory/</code> to replace the initials badge.",
        S["muted"]))
    elems.append(Spacer(1, 4 * mm))

    # ── 2-column card grid ────────────────────────────────────────────────────
    # Each grid cell is card_outer_w wide.
    # A gap of `gap` pts separates the two columns:
    #   left cell:  RIGHTPADDING = gap/2  →  content = card_outer_w - gap/2
    #   right cell: LEFTPADDING  = gap/2  →  content = card_outer_w - gap/2
    # Total: 2 * card_outer_w = CONTENT_W  ✓
    gap = int(4 * mm)
    card_outer_w = CONTENT_W / 2
    card_w = card_outer_w - gap / 2   # actual card content width

    names = list(frameworks.keys())
    badge_cycle = _BADGE_COLORS
    card_rows = []
    for i in range(0, len(names), 2):
        left_name = names[i]
        right_name = names[i + 1] if i + 1 < len(names) else None
        left_card  = _reg_framework_card(left_name,  frameworks[left_name],  card_w, badge_cycle[i % len(badge_cycle)])
        right_card = _reg_framework_card(right_name, frameworks[right_name], card_w, badge_cycle[(i + 1) % len(badge_cycle)]) \
                     if right_name else Spacer(card_w, 1)
        card_rows.append([left_card, right_card])

    grid_ts = TableStyle([
        ("LEFTPADDING",   (0, 0), (0, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, -1), gap // 2),
        ("LEFTPADDING",   (1, 0), (1, -1), gap // 2),
        ("RIGHTPADDING",  (1, 0), (1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), gap),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])
    elems.append(Table(card_rows, colWidths=[card_outer_w, card_outer_w], style=grid_ts))

    return elems


# ── Data Geography section ────────────────────────────────────────────────────

def _data_geography_section(report: Report, S: dict) -> list:
    """Build the Data Geography & Sovereignty world-map section."""
    regions: list[tuple[str, str, str | None]] = getattr(report, "detected_regions", [])

    elems: list = [
        *_section_header("Data Geography & Sovereignty", S),
        Paragraph(
            "The map below plots the geographic footprint of cloud infrastructure "
            "detected in the Terraform configuration. Each marker shows a region "
            "where data may be processed or stored — a critical factor for data "
            "sovereignty, residency compliance, and cross-border transfer assessments.",
            S["muted"],
        ),
        Spacer(1, 4 * mm),
    ]

    # World map drawing
    map_h = CONTENT_W * 0.48
    elems.append(_WorldMapFlowable(CONTENT_W, map_h, regions))
    elems.append(Paragraph(
        "Map tiles © <a href='https://carto.com/attributions'>CARTO</a> · "
        "© <a href='https://www.openstreetmap.org/copyright'>OpenStreetMap</a> contributors, ODbL",
        S["muted"],
    ))
    elems.append(Spacer(1, 2 * mm))

    # Legend (provider colour key) — only show providers present in this report
    _all_legend = [
        ("aws",      colors.HexColor("#f97316"), "● AWS"),
        ("azure",    colors.HexColor("#2b7fff"), "● Azure"),
        ("gcp",      colors.HexColor("#22c55e"), "● GCP"),
        ("alicloud", colors.HexColor("#ff6a00"), "● Alibaba Cloud"),
        ("yandex",   colors.HexColor("#fcdb03"), "● Yandex Cloud"),
        ("oci",      colors.HexColor("#c74634"), "● Oracle Cloud"),
    ]
    present_providers = {p.lower() for _, p in regions}
    legend_items = [(col, label) for key, col, label in _all_legend if key in present_providers]
    if not legend_items:
        legend_items = [(col, label) for _, col, label in _all_legend[:3]]
    col_w_each = CONTENT_W / len(legend_items)
    legend_cells = [
        Paragraph(
            f'<font color="#{_hex(col)}" name="Helvetica-Bold">{label}</font>',
            ParagraphStyle("leg", fontName="Helvetica", fontSize=8,
                           leading=12, textColor=C_DARK),
        )
        for col, label in legend_items
    ]
    legend_table = Table(
        [legend_cells],
        colWidths=[col_w_each] * len(legend_items),
        style=TableStyle([
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]),
    )
    elems.append(legend_table)
    elems.append(Spacer(1, 5 * mm))

    if not regions:
        elems.append(Paragraph(
            "No explicit region or location attributes were detected in the Terraform "
            "configuration. Ensure provider blocks and resource definitions declare "
            "regions explicitly to enable sovereignty validation.",
            ParagraphStyle("warn", fontName="Helvetica", fontSize=9, leading=13,
                           textColor=C_ORANGE, backColor=C_ORANGE_LT,
                           borderPadding=(6, 8, 6, 8)),
        ))
        return elems

    # Detected regions table
    elems += _section_header("Detected Regions", S)
    unique_regions = sorted(set(regions), key=lambda x: (x[1].lower(), x[0].lower()))
    elems.append(Paragraph(
        f"{len(unique_regions)} unique cloud region(s) identified across the Terraform "
        "configuration.",
        S["muted"],
    ))
    elems.append(Spacer(1, 3 * mm))

    header_row = ["Region Identifier", "Provider", "Geographic Location"]
    data_rows = []
    for region_name, provider in unique_regions:
        label = _REGION_LABELS.get(region_name.strip().lower(), "")
        if not label:
            coords = _REGION_COORDS.get(region_name.strip().lower())
            if coords:
                lat, lon = coords
                ns = "N" if lat >= 0 else "S"
                ew = "E" if lon >= 0 else "W"
                label = f"{abs(lat):.1f}°{ns}, {abs(lon):.1f}°{ew}"
        data_rows.append((region_name, provider.upper(), label or "—"))

    ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
    ])
    prov_color_map = {
        "AWS":      C_ORANGE,
        "AZURE":    C_BLUE,
        "GCP":      C_GREEN,
        "ALICLOUD": colors.HexColor("#ff6a00"),
        "YANDEX":   colors.HexColor("#fcdb03"),
        "OCI":      colors.HexColor("#c74634"),
    }
    for i, (_, provider, _) in enumerate(data_rows, start=1):
        c = prov_color_map.get(provider, C_GREY)
        ts.add("TEXTCOLOR", (1, i), (1, i), c)
        ts.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")

    col_w = [5.5 * cm, 2.5 * cm, CONTENT_W - 8 * cm]
    all_rows = [header_row] + [list(r) for r in data_rows]
    elems.append(Table(
        [
            [Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
             for j, v in enumerate(row)]
            if i == 0 else
            [Paragraph(str(v), S["body_sm"]) for v in row]
            for i, row in enumerate(all_rows)
        ],
        colWidths=col_w, style=ts,
    ))

    return elems


# ── Table of Contents section ─────────────────────────────────────────────────

def _toc_section(S: dict) -> list:
    """Build the Table of Contents page."""
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(
            "TOCLevel0",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=17,
            textColor=C_NAVY,
            leftIndent=0,
            spaceAfter=3,
            spaceBefore=5,
        ),
        ParagraphStyle(
            "TOCLevel1",
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=C_DARK,
            leftIndent=1 * cm,
            spaceAfter=1,
        ),
    ]
    toc.dotsMinLevel = 0

    return [
        # Header drawn directly (not via _section_header to avoid circular TOC entry)
        Spacer(1, 4 * mm),
        Table(
            [[Paragraph("Table of Contents", S["h2"])]],
            colWidths=[CONTENT_W],
            style=TableStyle([
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBEFORE",    (0, 0), (0, 0), 3, C_BLUE),
                ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_LT),
            ]),
        ),
        Spacer(1, 6 * mm),
        toc,
    ]


# ── Executive Decision Brief ──────────────────────────────────────────────────

def _executive_decision_brief(report: "Report", S: dict, baseline: dict | None = None) -> list:
    """Generate the Executive Decision Brief with 3 actionable decision cards."""
    root_causes = _analyse_root_causes(report)
    score, label, score_color = _risk_score(report)
    total_min, total_max, _ = _financial_exposure(report)

    decisions: list[dict] = []

    # Decision 1: Top root cause by ROI (quick win)
    if root_causes:
        top = root_causes[0]
        impact_pts = f"{top['score_impact']:.1f} pts risk score reduction"
        decisions.append({
            "num": "1",
            "color": C_RED,
            "title": top["title"],
            "impact": impact_pts,
            "effort": f"{top['effort_days']} engineering day(s)",
            "action": "DO NOW",
            "action_color": C_RED,
            "detail": top["fix"][:180],
        })
    else:
        decisions.append({
            "num": "1",
            "color": C_GREEN,
            "title": "No high-ROI quick wins detected",
            "impact": "All controls are passing or waived",
            "effort": "—",
            "action": "MONITOR",
            "action_color": C_GREEN,
            "detail": "Continue monitoring and re-run after infrastructure changes.",
        })

    # Decision 2: Regulatory exposure — sovereign or security pillar GDPR failures
    sov_fails = [cr for cr in report.results
                 if cr.status == "FAIL" and (cr.control.pillar or "").lower() in ("sovereign", "security")]
    gdpr_fails = [cr for cr in sov_fails
                  if any("gdpr" in (reg.get("framework", "")).lower()
                         for reg in cr.control.regulatory_mapping)]
    reg_min = reg_max = 0
    for cr in sov_fails:
        pillar = (cr.control.pillar or "security").lower()
        sev = (cr.control.severity or "low").lower()
        entry = _PILLAR_EXPOSURE_USD.get(pillar, _PILLAR_EXPOSURE_USD["security"])
        _, _, ranges = entry
        emin, emax = ranges.get(sev, (0, 0))
        reg_min += emin
        reg_max += emax

    if sov_fails:
        gdpr_note = f"{len(gdpr_fails)} GDPR-mapped control(s) failing. " if gdpr_fails else ""
        decisions.append({
            "num": "2",
            "color": C_PURPLE,
            "title": f"Regulatory Exposure: {len(sov_fails)} sovereign/security control(s) failing",
            "impact": f"{gdpr_note}Estimated fine exposure: {_fmt_usd(reg_min)} – {_fmt_usd(reg_max)}",
            "effort": "Legal & compliance review required",
            "action": "LEGAL INPUT NEEDED",
            "action_color": C_PURPLE,
            "detail": (
                "Engage Data Protection Officer and legal counsel. "
                "Review GDPR Art. 83 applicability for each failing sovereign control. "
                "Document risk acceptance or accelerate remediation timeline."
            ),
        })
    else:
        decisions.append({
            "num": "2",
            "color": C_GREEN,
            "title": "No regulatory / sovereign control failures detected",
            "impact": "GDPR Art. 83 and NIS2 exposure appears contained",
            "effort": "Periodic review recommended",
            "action": "SCHEDULE",
            "action_color": C_BLUE,
            "detail": (
                "Schedule a quarterly regulatory alignment review to ensure "
                "new infrastructure changes do not introduce data residency violations."
            ),
        })

    # Decision 3: Expiring waivers or second-best ROI root cause
    waived_crs = [cr for cr in report.results if cr.status == "WAIVED"]
    from datetime import date as _date
    expiring_waivers = []
    for cr in waived_crs:
        if hasattr(cr, "waived_expires") and cr.waived_expires:
            try:
                exp_date = _date.fromisoformat(str(cr.waived_expires))
                days_left = (exp_date - _date.today()).days
                if days_left <= 90:
                    expiring_waivers.append((cr, days_left))
            except Exception:
                pass

    if expiring_waivers:
        soonest = sorted(expiring_waivers, key=lambda x: x[1])[0]
        cr_exp, days_left = soonest
        decisions.append({
            "num": "3",
            "color": C_ORANGE,
            "title": f"Waiver expiring: {cr_exp.control.id} ({days_left} day(s) remaining)",
            "impact": f"Control reverts to FAIL status after expiry — affects risk score",
            "effort": "0.5 day(s) — waiver renewal or remediation decision",
            "action": "RENEW WAIVER",
            "action_color": C_ORANGE,
            "detail": (
                f"Review waiver for {cr_exp.control.id} ({cr_exp.control.title[:80]}). "
                "Either remediate the underlying finding to close the waiver, "
                "or document a renewed risk acceptance with updated expiry."
            ),
        })
    elif len(root_causes) >= 2:
        sec = root_causes[1]
        decisions.append({
            "num": "3",
            "color": C_BLUE,
            "title": sec["title"],
            "impact": f"{sec['score_impact']:.1f} pts risk score reduction",
            "effort": f"{sec['effort_days']} engineering day(s)",
            "action": "SCHEDULE",
            "action_color": C_BLUE,
            "detail": sec["fix"][:180],
        })
    else:
        decisions.append({
            "num": "3",
            "color": C_GREY,
            "title": "Review waiver register for accuracy",
            "impact": f"{len(waived_crs)} control(s) currently waived",
            "effort": "0.5 day(s) — periodic review",
            "action": "SCHEDULE",
            "action_color": C_BLUE,
            "detail": (
                "Confirm all active waivers are still valid and have not expired. "
                "Remove waivers for controls that have been remediated."
            ),
        })

    elems: list = [
        *_section_header("Executive Decision Brief", S),
        Paragraph(
            "Three decisions required from executive leadership based on this assessment. "
            "Each card summarises impact, effort, and the recommended action.",
            S["muted"],
        ),
        Spacer(1, 5 * mm),
    ]

    card_w = CONTENT_W
    badge_w = 1.4 * cm

    for dec in decisions:
        num_color = dec["color"]
        num_hex   = _hex(num_color)
        act_hex   = _hex(dec["action_color"])

        badge_para = Paragraph(
            f'<font name="Helvetica-Bold" size="16" color="white">{dec["num"]}</font>',
            ParagraphStyle("dec_badge", alignment=TA_CENTER, leading=20),
        )

        title_para = Paragraph(
            f'<font name="Helvetica-Bold" size="11" color="#{_hex(C_NAVY)}">{dec["title"]}</font>',
            ParagraphStyle("dec_title", leading=15),
        )
        action_para = Paragraph(
            f'<font name="Helvetica-Bold" size="10" color="#{act_hex}">[ {dec["action"]} ]</font>',
            ParagraphStyle("dec_action", alignment=TA_RIGHT, leading=13),
        )
        title_row = Table(
            [[title_para, action_para]],
            colWidths=[card_w - badge_w - 3 * cm - 10, 3 * cm],
            style=TableStyle([
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                ("TOPPADDING",    (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )

        info_rows = [
            ["Impact",  dec["impact"]],
            ["Effort",  dec["effort"]],
            ["Action",  dec["detail"]],
        ]
        info_table = Table(
            [
                [
                    Paragraph(f'<font name="Helvetica-Bold" size="8" color="#{_hex(C_GREY)}">{k}</font>',
                               ParagraphStyle("ik", leading=11)),
                    Paragraph(f'<font size="8" color="#{_hex(C_DARK)}">{v}</font>',
                               ParagraphStyle("iv", leading=11)),
                ]
                for k, v in info_rows
            ],
            colWidths=[1.6 * cm, card_w - badge_w - 1.6 * cm - 16],
            style=TableStyle([
                ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
                ("TOPPADDING",    (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW",     (0, 0), (-1, -2), 0.3, C_BORDER),
            ]),
        )

        content_cell = Table(
            [[title_row], [Spacer(1, 3 * mm)], [info_table]],
            colWidths=[card_w - badge_w - 14],
            style=TableStyle([
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]),
        )

        card = Table(
            [[badge_para, content_cell]],
            colWidths=[badge_w, card_w - badge_w],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (0, -1),  num_color),
                ("BACKGROUND",    (1, 0), (1, -1),  C_WHITE),
                ("BOX",           (0, 0), (-1, -1), 1.5, num_color),
                ("LINEBEFORE",    (1, 0), (1, -1),  3,   num_color),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (0, -1),  14),
                ("BOTTOMPADDING", (0, 0), (0, -1),  14),
                ("LEFTPADDING",   (0, 0), (0, -1),  0),
                ("RIGHTPADDING",  (0, 0), (0, -1),  0),
                ("TOPPADDING",    (1, 0), (1, -1),  8),
                ("BOTTOMPADDING", (1, 0), (1, -1),  8),
                ("LEFTPADDING",   (1, 0), (1, -1),  0),
                ("RIGHTPADDING",  (1, 0), (1, -1),  0),
            ]),
        )
        elems.append(card)
        elems.append(Spacer(1, 4 * mm))

    return elems


# ── Root Cause Analysis section ───────────────────────────────────────────────

def _root_cause_section(report: "Report", S: dict) -> list:
    """Build the Root Cause Analysis table section."""
    patterns = _analyse_root_causes(report)
    if not patterns:
        return []

    elems: list = [
        *_section_header("Root Cause Analysis", S),
        Paragraph(
            "Recurring infrastructure patterns that account for multiple control failures. "
            "Fixing each root cause closes multiple findings simultaneously, maximising remediation ROI.",
            S["muted"],
        ),
        Spacer(1, 4 * mm),
    ]

    hdr = ["Root Cause", "Controls\nAffected", "Findings\nClosed", "Score\nImpact", "Est. Effort", "Fix Summary"]
    col_ws = [
        CONTENT_W * 0.22,
        CONTENT_W * 0.09,
        CONTENT_W * 0.09,
        CONTENT_W * 0.09,
        CONTENT_W * 0.10,
        CONTENT_W * 0.41,
    ]

    rows: list[list] = [
        [Paragraph(h, S["tbl_header_left"] if i == 0 else S["tbl_header"]) for i, h in enumerate(hdr)]
    ]

    for pat in patterns:
        n_ctrl = len(pat["matched_controls"])
        n_find = pat["finding_count"]
        impact = f"{pat['score_impact']:.1f} pts"
        effort = f"{pat['effort_days']}d"
        rows.append([
            Paragraph(f'<b>{pat["title"]}</b>', S["body_sm"]),
            Paragraph(str(n_ctrl), S["body_sm"]),
            Paragraph(str(n_find), S["body_sm"]),
            Paragraph(impact, S["body_sm"]),
            Paragraph(effort, S["body_sm"]),
            Paragraph(pat["fix"][:200], S["body_sm"]),
        ])

    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
        ("ALIGN",         (5, 0), (5, -1),  "LEFT"),
    ])
    elems.append(Table(rows, colWidths=col_ws, style=ts))
    return elems


# ── Remediation Roadmap section ───────────────────────────────────────────────

def _remediation_roadmap_section(report: "Report", S: dict) -> list:
    """Build the ROI-ranked remediation roadmap section."""
    patterns = _analyse_root_causes(report)
    if not patterns:
        return []

    elems: list = [
        *_section_header("Remediation Roadmap", S),
        Paragraph(
            "Remediations ranked by ROI (score impact per engineering day). "
            "Address DO NOW items first for maximum risk reduction with minimal effort.",
            S["muted"],
        ),
        Spacer(1, 4 * mm),
    ]

    hdr = ["#", "Remediation", "Score\nImpact", "Findings", "Effort", "Priority"]
    col_ws = [
        0.5 * cm,
        CONTENT_W * 0.38,
        CONTENT_W * 0.10,
        CONTENT_W * 0.09,
        CONTENT_W * 0.10,
        CONTENT_W * 0.17,
    ]

    rows: list[list] = [
        [Paragraph(h, S["tbl_header"] if i != 1 else S["tbl_header_left"]) for i, h in enumerate(hdr)]
    ]

    for rank, pat in enumerate(patterns, start=1):
        roi = pat["roi"]
        effort = pat["effort_days"]
        if roi > 5:
            priority_label = "DO NOW"
            p_color = C_RED
        elif roi >= 2:
            priority_label = "SCHEDULE"
            p_color = C_ORANGE
        else:
            priority_label = "PLAN"
            p_color = C_BLUE

        ph = _hex(p_color)
        rows.append([
            Paragraph(str(rank), S["body_sm"]),
            Paragraph(f'<b>{pat["title"]}</b>', S["body_sm"]),
            Paragraph(f"{pat['score_impact']:.1f} pts", S["body_sm"]),
            Paragraph(str(pat["finding_count"]), S["body_sm"]),
            Paragraph(f"{effort}d", S["body_sm"]),
            Paragraph(
                f'<font name="Helvetica-Bold" color="#{ph}">{priority_label}</font>',
                ParagraphStyle("prio", fontSize=8, leading=11, alignment=TA_CENTER),
            ),
        ])

    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("ALIGN",         (1, 0), (1, -1),  "LEFT"),
    ])

    # Colour the priority column per row
    for i, pat in enumerate(patterns, start=1):
        roi = pat["roi"]
        effort = pat["effort_days"]
        if roi > 5:
            bg = C_RED_LT
        elif roi >= 2:
            bg = C_ORANGE_LT
        else:
            bg = C_BLUE_LT
        ts.add("BACKGROUND", (5, i), (5, i), bg)

    elems.append(Table(rows, colWidths=col_ws, style=ts))
    return elems


# ── Risk & Financial Impact section ──────────────────────────────────────────

def _risk_financial_section(report: Report, S: dict, baseline: dict | None = None) -> list:
    """Build the Executive Risk Dashboard section (risk score + financial exposure)."""
    score, label, score_color = _risk_score(report)
    total_min, total_max, breakdown = _financial_exposure(report)

    sev_order = ["critical", "high", "medium", "low"]
    sev_label_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
    sev_color_map = {
        "critical": C_RED, "high": C_ORANGE, "medium": C_YELLOW, "low": C_BLUE,
    }

    elems: list = [*_section_header("Executive Risk Dashboard", S)]

    # ── 1. Risk Score card ────────────────────────────────────────────────────
    elems += [*_section_header("Overall Risk Score", S, toc_level=1)]

    elems.append(Paragraph(
        "The Risk Score aggregates all control failures weighted by severity. "
        "A score of 0 represents full compliance; 100 represents maximum exposure across all controls.",
        S["muted"],
    ))
    elems.append(Spacer(1, 4 * mm))

    # Score number box (left) + gauge bar (right)
    score_hex = _hex(score_color)
    score_cell = Table(
        [[
            Paragraph(
                f'<font color="#{score_hex}" size="36"><b>{score}</b></font>'
                f'<br/><font size="9" color="#{score_hex}"><b>/ 100</b></font>',
                ParagraphStyle("sc_num", fontName="Helvetica-Bold", fontSize=36,
                               leading=40, alignment=TA_CENTER),
            ),
        ]],
        colWidths=[3.5 * cm],
        style=TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_LT),
            ("BOX",           (0, 0), (-1, -1), 2, score_color),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]),
    )

    label_hex = score_hex
    badge_cell = Table(
        [[Paragraph(
            f'<font color="#{label_hex}"><b>● {label}</b></font>',
            ParagraphStyle("sc_badge", fontName="Helvetica-Bold", fontSize=11,
                           leading=14, alignment=TA_CENTER),
        )]],
        colWidths=[3.5 * cm],
        style=TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_LT),
            ("BOX",           (0, 0), (-1, -1), 2, score_color),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ]),
    )

    fail_count = report.total_fail
    total_count = report.controls_run
    gauge_bar   = _RiskGaugeBar(score, CONTENT_W - 3.5 * cm - 6 * mm, height=28)
    gauge_desc  = Paragraph(
        f"<b>{fail_count}</b> of <b>{total_count}</b> controls are currently failing. "
        f"The weighted failure ratio drives the {label.lower()} risk posture. "
        "Remediating critical and high-severity findings will have the greatest score impact.",
        S["body_sm"],
    )

    score_col_w  = 3.5 * cm
    gauge_col_w  = CONTENT_W - score_col_w - 4 * mm
    score_layout = Table(
        [[score_cell, Table([[gauge_bar], [Spacer(1, 3 * mm)], [gauge_desc]],
                            colWidths=[gauge_col_w],
                            style=TableStyle([
                                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                ("TOPPADDING",   (0, 0), (-1, -1), 8),
                                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                            ]))]],
        colWidths=[score_col_w, gauge_col_w + 4 * mm],
        style=TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]),
    )
    elems.append(score_layout)

    # ── Baseline delta badge (if baseline provided) ───────────────────────────
    if baseline is not None:
        prev_score = baseline.get("score")
        if prev_score is not None:
            delta = score - int(prev_score)
            if delta > 0:
                delta_text = f"▲ +{delta} pts vs. baseline (worsened)"
                delta_color = C_RED
            elif delta < 0:
                delta_text = f"▼ {delta} pts vs. baseline (improved)"
                delta_color = C_GREEN
            else:
                delta_text = "= No change vs. baseline"
                delta_color = C_GREY
            elems.append(Spacer(1, 3 * mm))
            elems.append(Table(
                [[Paragraph(
                    f'<font name="Helvetica-Bold" size="9" color="#{_hex(delta_color)}">{delta_text}</font>',
                    ParagraphStyle("delta", alignment=TA_CENTER, leading=13),
                )]],
                colWidths=[CONTENT_W],
                style=TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_LT),
                    ("BOX",           (0, 0), (-1, -1), 1, delta_color),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ]),
            ))

    elems.append(Spacer(1, 6 * mm))

    # ── 2. Risk Breakdown by Pillar ───────────────────────────────────────────
    elems.append(Paragraph("Risk Breakdown by Pillar", S["h3"]))
    elems.append(Spacer(1, 2 * mm))

    pillar_data: dict[str, dict] = {}
    for cr in report.results:
        pillar = (cr.control.pillar or "unknown").lower()
        if pillar not in pillar_data:
            pillar_data[pillar] = {"total_w": 0, "fail_w": 0, "fail": 0, "total": 0}
        w = _SEV_WEIGHTS.get((cr.control.severity or "low").lower(), 1)
        pillar_data[pillar]["total_w"] += w
        pillar_data[pillar]["total"]   += 1
        if cr.status == "FAIL":
            pillar_data[pillar]["fail_w"] += w
            pillar_data[pillar]["fail"]   += 1

    pillar_rows: list[list] = []
    for pillar in sorted(pillar_data.keys()):
        pd   = pillar_data[pillar]
        pscore = int(pd["fail_w"] / max(pd["total_w"], 1) * 100)
        if pscore >= 70:
            p_label, p_color = "CRITICAL", C_RED
        elif pscore >= 40:
            p_label, p_color = "HIGH",     C_ORANGE
        elif pscore >= 20:
            p_label, p_color = "MEDIUM",   C_YELLOW
        else:
            p_label, p_color = "LOW",      C_GREEN
        ctx_label, ctx_desc = _PILLAR_RISK_CONTEXT.get(pillar, ("—", "—"))
        ph = _hex(p_color)
        pillar_rows.append([
            Paragraph(pillar.title(), S["body_sm"]),
            Paragraph(f'<font color="#{ph}"><b>{pscore}</b></font>', S["body_sm"]),
            Paragraph(f'<font color="#{ph}"><b>{p_label}</b></font>', S["body_sm"]),
            Paragraph(f'{pd["fail"]}/{pd["total"]}', S["body_sm"]),
            Paragraph(ctx_desc, S["body_sm"]),
        ])

    pillar_hdr = ["Pillar", "Score", "Category", "Failing", "Risk Context"]
    col_ws = [2.8 * cm, 1.4 * cm, 2.2 * cm, 1.6 * cm, CONTENT_W - 8 * cm]
    elems.append(Table(
        [[Paragraph(h, S["tbl_header_left"]) for h in pillar_hdr]] + pillar_rows,
        colWidths=col_ws,
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ]),
    ))
    elems.append(Spacer(1, 6 * mm))

    # ── 3. Financial Exposure (own page) ──────────────────────────────────────
    elems.append(PageBreak())
    elems += [*_section_header("Estimated Financial Exposure", S, toc_level=1)]

    elems.append(Paragraph(
        "Financial exposure is estimated based on severity-weighted failure counts, "
        "referencing IBM Cost of a Data Breach Report 2024 (global average breach cost $4.88M), "
        "Gartner infrastructure downtime benchmarks, and GDPR/NIS2 maximum penalty structures. "
        "Figures represent a plausible range, not a guaranteed outcome.",
        S["muted"],
    ))
    elems.append(Spacer(1, 4 * mm))

    # Total exposure highlight box
    exp_text = (
        f"Total Estimated Exposure:  "
        f"<b>{_fmt_usd(total_min)}</b>  –  <b>{_fmt_usd(total_max)}</b>"
        if total_max > 0 else
        "No failing controls — exposure within acceptable range."
    )
    elems.append(Table(
        [[Paragraph(exp_text, ParagraphStyle(
            "exp_total", fontName="Helvetica-Bold", fontSize=13, leading=18,
            textColor=C_NAVY, alignment=TA_CENTER,
        ))]],
        colWidths=[CONTENT_W],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_BLUE_LT),
            ("BOX",           (0, 0), (-1, -1), 1.5, C_BLUE),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ]),
    ))
    elems.append(Spacer(1, 4 * mm))

    # Breakdown by risk type (pillar-aware exposure table)
    risk_type_rows = _financial_exposure_by_risk_type(report)
    if risk_type_rows:
        rt_hdr = ["Risk Type", "Pillars", "Failing\nControls", "Min Exposure\n(USD)", "Max Exposure\n(USD)"]
        col_ws_fin = [
            CONTENT_W * 0.24,
            CONTENT_W * 0.20,
            CONTENT_W * 0.10,
            CONTENT_W * 0.20,
            CONTENT_W * 0.20,
        ]
        rt_table_rows: list[list] = [
            [Paragraph(h, S["tbl_header_left"] if i == 0 else S["tbl_header"]) for i, h in enumerate(rt_hdr)]
        ]
        for row in risk_type_rows:
            rt_table_rows.append([
                Paragraph(f'<b>{row["risk_type"]}</b>', S["body_sm"]),
                Paragraph(row["pillars"], S["body_sm"]),
                Paragraph(str(row["fail_count"]), S["body_sm"]),
                Paragraph(_fmt_usd(row["min_usd"]), S["body_sm"]),
                Paragraph(_fmt_usd(row["max_usd"]), S["body_sm"]),
            ])
        elems.append(Table(
            rt_table_rows,
            colWidths=col_ws_fin,
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("LEADING",       (0, 0), (-1, -1), 11),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("ALIGN",         (2, 0), (-1, -1), "CENTER"),
                ("ALIGN",         (0, 0), (1, -1),  "LEFT"),
            ]),
        ))
        elems.append(Spacer(1, 3 * mm))

    elems.append(Paragraph(
        "⚠ Disclaimer: These estimates are indicative only and should not be used as formal "
        "financial projections. Actual costs depend on incident scope, jurisdiction, insurance "
        "coverage, and organisational response capability. Engage legal and risk advisory teams "
        "for formal exposure quantification.",
        ParagraphStyle("disclaimer", fontName="Helvetica-Oblique", fontSize=7.5,
                       leading=11, textColor=C_GREY),
    ))
    return elems


class _WAFDocTemplate(BaseDocTemplate):
    """BaseDocTemplate that registers TOC entries from _TOCEntry flowables."""

    def afterFlowable(self, flowable: object) -> None:
        if isinstance(flowable, _TOCEntry):
            self.notify("TOCEntry", (flowable._level, flowable._text, self.page))


# ── Hex color helper ──────────────────────────────────────────────────────────

def _hex(color: colors.Color) -> str:
    """Return 6-char hex string for a ReportLab color (no #)."""
    return "{:02x}{:02x}{:02x}".format(
        int(color.red * 255), int(color.green * 255), int(color.blue * 255)
    )


# ── Run change tracking section ───────────────────────────────────────────────

def _changes_section(diff: dict, S: dict) -> list:
    """Generate a 'Changes from Previous Run' section for the PDF report."""
    from datetime import datetime

    regressions = diff.get("regressions", [])
    improvements = diff.get("improvements", [])
    other_changes = diff.get("other_changes", [])
    score_delta = diff.get("score_delta", 0)
    prev_ts = diff.get("previous_generated_at", "")
    prev_id = diff.get("previous_run_id", "")
    total_changes = len(regressions) + len(improvements) + len(other_changes)

    # Format previous run timestamp
    try:
        dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
        ts_display = dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        ts_display = prev_ts or "unknown"

    elems: list = []

    # ── Section heading
    elems.append(
        Paragraph("Run Change Tracking", S["h1"])
    )
    elems.append(Spacer(1, 4 * mm))
    elems.append(
        Paragraph(
            f"Comparing against previous run from <b>{ts_display}</b>"
            + (f" &nbsp;<font color='#64748b'>({prev_id})</font>" if prev_id else ""),
            S["body"],
        )
    )
    elems.append(Spacer(1, 6 * mm))

    # ── Score delta card
    if score_delta > 0:
        delta_color = C_RED
        delta_label = f"+{score_delta} pts (worse)"
        delta_bg = C_RED_LT
    elif score_delta < 0:
        delta_color = C_GREEN
        delta_label = f"{score_delta} pts (improved)"
        delta_bg = C_GREEN_LT
    else:
        delta_color = C_GREY
        delta_label = "no change"
        delta_bg = C_GREY_LT

    score_row = [
        Paragraph(f"<b>Risk Score Delta</b>", S["body"]),
        Paragraph(f"<font color='#{_hex(delta_color)}'><b>{delta_label}</b></font>", S["body"]),
        Paragraph(f"<b>Controls Changed</b>", S["body"]),
        Paragraph(f"<b>{total_changes}</b>", S["body"]),
    ]
    t = Table([score_row], colWidths=[CONTENT_W * 0.3, CONTENT_W * 0.2, CONTENT_W * 0.3, CONTENT_W * 0.2])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_GREY_LT),
        ("ROUNDEDCORNERS", [4]),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 6 * mm))

    if total_changes == 0:
        elems.append(
            Paragraph(
                "No control status changes detected since the previous run. "
                "All controls maintained their previous state.",
                S["body"],
            )
        )
        return elems

    _SEV_COLORS_PDF = {
        "critical": C_RED,
        "high": C_ORANGE,
        "medium": C_YELLOW,
        "low": C_BLUE,
    }

    def _change_rows(entries: list[dict], from_label: str, to_label: str,
                     to_color: "colors.Color") -> list:
        rows = []
        for e in entries:
            sev = (e.get("severity") or "low").lower()
            sev_c = _SEV_COLORS_PDF.get(sev, C_GREY)
            rows.append([
                Paragraph(
                    f"<font color='#{_hex(sev_c)}'><b>[{sev.upper()}]</b></font>",
                    S["body_sm"],
                ),
                Paragraph(f"<b>{e['control_id']}</b>", S["body_sm"]),
                Paragraph(e.get("title", ""), S["body_sm"]),
                Paragraph(
                    f"<font color='#64748b'>{from_label}</font> → "
                    f"<font color='#{_hex(to_color)}'><b>{to_label}</b></font>",
                    S["body_sm"],
                ),
            ])
        return rows

    col_w = [CONTENT_W * 0.10, CONTENT_W * 0.18, CONTENT_W * 0.52, CONTENT_W * 0.20]

    # ── Regressions
    if regressions:
        elems.append(
            Paragraph(
                f"<font color='#{_hex(C_RED)}'><b>Regressions</b></font> "
                f"<font color='#64748b'>— {len(regressions)} control(s) newly FAILED</font>",
                S["h2"],
            )
        )
        elems.append(Spacer(1, 2 * mm))
        header = [
            Paragraph("<b>Severity</b>", S["body_sm"]),
            Paragraph("<b>Control</b>", S["body_sm"]),
            Paragraph("<b>Title</b>", S["body_sm"]),
            Paragraph("<b>Transition</b>", S["body_sm"]),
        ]
        rows = [header] + _change_rows(regressions, "PASS", "FAIL", C_RED)
        t = Table(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_RED_LT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 5 * mm))

    # ── Improvements
    if improvements:
        elems.append(
            Paragraph(
                f"<font color='#{_hex(C_GREEN)}'><b>Improvements</b></font> "
                f"<font color='#64748b'>— {len(improvements)} control(s) left FAIL state</font>",
                S["h2"],
            )
        )
        elems.append(Spacer(1, 2 * mm))
        header = [
            Paragraph("<b>Severity</b>", S["body_sm"]),
            Paragraph("<b>Control</b>", S["body_sm"]),
            Paragraph("<b>Title</b>", S["body_sm"]),
            Paragraph("<b>Transition</b>", S["body_sm"]),
        ]

        def _impr_rows(entries: list[dict]) -> list:
            rows = []
            for e in entries:
                sev = (e.get("severity") or "low").lower()
                sev_c = _SEV_COLORS_PDF.get(sev, C_GREY)
                to_s = e.get("to", "PASS")
                to_c = {"PASS": C_GREEN, "WAIVED": C_PURPLE, "SKIP": C_GREY}.get(to_s, C_GREEN)
                rows.append([
                    Paragraph(
                        f"<font color='#{_hex(sev_c)}'><b>[{sev.upper()}]</b></font>",
                        S["body_sm"],
                    ),
                    Paragraph(f"<b>{e['control_id']}</b>", S["body_sm"]),
                    Paragraph(e.get("title", ""), S["body_sm"]),
                    Paragraph(
                        f"<font color='#64748b'>FAIL</font> → "
                        f"<font color='#{_hex(to_c)}'><b>{to_s}</b></font>",
                        S["body_sm"],
                    ),
                ])
            return rows

        rows = [header] + _impr_rows(improvements)
        t = Table(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_GREEN_LT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 5 * mm))

    # ── Other status changes
    if other_changes:
        elems.append(
            Paragraph(
                f"<font color='#{_hex(C_YELLOW)}'><b>Other Status Changes</b></font> "
                f"<font color='#64748b'>— {len(other_changes)} control(s)</font>",
                S["h2"],
            )
        )
        elems.append(Spacer(1, 2 * mm))
        header = [
            Paragraph("<b>Severity</b>", S["body_sm"]),
            Paragraph("<b>Control</b>", S["body_sm"]),
            Paragraph("<b>Title</b>", S["body_sm"]),
            Paragraph("<b>Transition</b>", S["body_sm"]),
        ]

        def _other_rows(entries: list[dict]) -> list:
            rows = []
            for e in entries:
                sev = (e.get("severity") or "low").lower()
                sev_c = _SEV_COLORS_PDF.get(sev, C_GREY)
                rows.append([
                    Paragraph(
                        f"<font color='#{_hex(sev_c)}'><b>[{sev.upper()}]</b></font>",
                        S["body_sm"],
                    ),
                    Paragraph(f"<b>{e['control_id']}</b>", S["body_sm"]),
                    Paragraph(e.get("title", ""), S["body_sm"]),
                    Paragraph(
                        f"<font color='#64748b'>{e.get('from', '?')} → {e.get('to', '?')}</font>",
                        S["body_sm"],
                    ),
                ])
            return rows

        rows = [header] + _other_rows(other_changes)
        t = Table(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_YELLOW_LT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elems.append(t)

    return elems


# ── Part divider ─────────────────────────────────────────────────────────────

_PART_ACCENT: dict[str, tuple] = {
    "I":   (colors.HexColor("#c0392b"), colors.HexColor("#fadbd8")),   # red  — alerts
    "II":  (colors.HexColor("#2b7fff"), colors.HexColor("#dbeafe")),   # blue — executive
    "III": (colors.HexColor("#059669"), colors.HexColor("#d1fae5")),   # green — risk/sustain
    "IV":  (colors.HexColor("#7c3aed"), colors.HexColor("#ede9fe")),   # purple — technical
    "V":   (colors.HexColor("#f97316"), colors.HexColor("#ffedd5")),   # orange — remediation
    "APP": (colors.HexColor("#64748b"), colors.HexColor("#f1f5f9")),   # grey — appendix
}


class _PartDivider(Flowable):
    """Full-page dark background part divider (rendered in a full-page, margin-free frame).

    The "divider" PageTemplate uses a zero-margin Frame that covers the entire
    page, so this flowable fills the page edge-to-edge with no white borders.
    A blank onPage callback suppresses the normal header/footer chrome.
    """

    def __init__(self, part_id: str, title: str, subtitle: str, audience: str) -> None:
        Flowable.__init__(self)
        # Dimensions match the full-page Frame used by the "divider" template
        self.width  = PAGE_W
        self.height = PAGE_H
        self._part_id  = part_id
        self._title    = title
        self._subtitle = subtitle
        self._audience = audience

    def getPlainText(self) -> str:  # picked up by _WAFDocTemplate → TOC
        return f"{self._part_id}  {self._title}"

    def draw(self) -> None:
        c = self.canv
        accent, _accent_lt = _PART_ACCENT.get(self._part_id, (C_NAVY, C_BLUE_LT))

        c.saveState()

        # Full-page navy background (no rounded corners — fills edge-to-edge)
        c.setFillColor(C_NAVY)
        c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

        # Accent left stripe (full height)
        c.setFillColor(accent)
        c.rect(0, 0, 8, PAGE_H, fill=1, stroke=0)

        # Vertical centre point for the text block
        mid_y = PAGE_H / 2

        # "PART  X" label
        c.setFillColor(accent)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(MARGIN + 8, mid_y + 55 * mm, f"PART  {self._part_id}")

        # Separator line
        c.setStrokeColor(colors.HexColor("#2d3d5a"))
        c.setLineWidth(1)
        c.line(MARGIN + 8, mid_y + 48 * mm, PAGE_W - MARGIN, mid_y + 48 * mm)

        # Large title
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", 32)
        c.drawString(MARGIN + 8, mid_y + 22 * mm, self._title)

        # Subtitle
        c.setFillColor(colors.HexColor("#94a3b8"))
        c.setFont("Helvetica", 13)
        # Wrap subtitle if it's long
        max_w = PAGE_W - 2 * MARGIN - 20
        words = self._subtitle.split()
        lines, current = [], ""
        for word in words:
            test = (current + " " + word).strip()
            if c.stringWidth(test, "Helvetica", 13) <= max_w:
                current = test
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        for i, line in enumerate(lines[:2]):
            c.drawString(MARGIN + 8, mid_y + 4 * mm - i * 17, line)

        # Audience badge pill
        badge_text = f"  For:  {self._audience}  "
        badge_y = mid_y - 25 * mm
        c.setFont("Helvetica", 9)
        bw = c.stringWidth(badge_text, "Helvetica", 9) + 10
        c.setFillColor(accent)
        c.roundRect(MARGIN + 8, badge_y, bw, 18, 5, fill=1, stroke=0)
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN + 13, badge_y + 5, badge_text)

        # WAF++ wordmark at bottom-right
        c.setFillColor(colors.HexColor("#2d3d5a"))
        c.setFont("Helvetica-Bold", 10)
        c.drawRightString(PAGE_W - MARGIN, 12 * mm, "WAF")
        waf_w = c.stringWidth("WAF", "Helvetica-Bold", 10)
        c.setFillColor(accent)
        c.drawString(PAGE_W - MARGIN - c.stringWidth("++", "Helvetica-Bold", 10), 12 * mm, "++")

        c.restoreState()


def _part_divider(part_id: str, title: str, subtitle: str, audience: str) -> list:
    """Return story elements for a full-page part divider.

    Wraps the divider with ``NextPageTemplate`` switches so the page has:
    - no normal header/footer chrome (uses the "divider" template)
    - full-page navy background edge-to-edge
    The following page automatically reverts to the "normal" template.
    """
    return [
        NextPageTemplate("divider"),
        PageBreak(),
        _TOCEntry(0, f"{part_id}  ·  {title}"),
        _PartDivider(part_id, title, subtitle, audience),
        NextPageTemplate("normal"),
    ]


# ── Carbon Footprint section ──────────────────────────────────────────────────

_C_GREEN_DARK  = colors.HexColor("#059669")
_C_GREEN_MID   = colors.HexColor("#34d399")
_C_GREEN_PALE  = colors.HexColor("#d1fae5")
_C_AMBER       = colors.HexColor("#f59e0b")
_C_AMBER_PALE  = colors.HexColor("#fef3c7")


def _carbon_section(carbon: "CarbonResult", S: dict) -> list:
    """Build the Carbon Footprint & Sustainability section."""
    from wafpass.carbon import CarbonResult  # local import – optional feature

    # Build the region disclaimer dynamically
    _all_region_names = [r for r, _p, _z in carbon.detected_regions] if carbon.detected_regions else []
    _other_regions = [r for r in _all_region_names if r != carbon.primary_region]
    if _other_regions:
        _region_note = (
            f"<b>Region used for calculations: {carbon.primary_region}</b> "
            f"(grid intensity: {carbon.primary_intensity:.3f} kgCO2e/kWh). "
            f"Additional regions detected in the IaC code — "
            + ", ".join(f"<i>{r}</i>" for r in _other_regions)
            + " — are not included in this estimate because emission factors for "
            "all provider regions are not available in the current dataset. "
            "Only regions with a known grid intensity factor are eligible; "
            "the highest-priority major-provider region is selected when multiple "
            "eligible regions are present."
        )
    elif carbon.detected_regions:
        _region_note = (
            f"<b>Region used for calculations: {carbon.primary_region}</b> "
            f"(grid intensity: {carbon.primary_intensity:.3f} kgCO2e/kWh). "
            "This is the only region detected in the IaC code that has a known "
            "grid emission intensity factor in the current dataset."
        )
    else:
        _region_note = (
            f"<b>Region used for calculations: {carbon.primary_region}</b> "
            f"(grid intensity: {carbon.primary_intensity:.3f} kgCO2e/kWh) — "
            "no deployment region could be detected from the IaC code; "
            "the EU Central default was applied."
        )

    elems: list = [
        *_section_header("Carbon Footprint & Sustainability", S),
        Paragraph(
            "Estimated monthly cloud infrastructure carbon footprint derived from "
            "resource types, instance counts, and the grid emission factor of the "
            "detected deployment region. "
            "Figures are directional estimates — actual emissions depend on workload "
            "utilisation and cloud provider renewable-energy purchases.",
            S["muted"],
        ),
        Spacer(1, 2 * mm),
        Paragraph(_region_note, S["muted"]),
        Spacer(1, 4 * mm),
    ]

    # ── KPI strip ─────────────────────────────────────────────────────────────
    def _co2_style(name: str, color) -> ParagraphStyle:
        return ParagraphStyle(name, fontName="Helvetica-Bold", fontSize=18,
                              leading=22, textColor=color, alignment=TA_CENTER)

    monthly_label = f"{carbon.total_monthly_co2e_kg:,.1f} kg"
    annual_label  = f"{carbon.total_annual_co2e_kg / 1000:,.2f} t"
    kwh_label     = f"{carbon.total_monthly_kwh:,.0f} kWh"

    kpi_data = [
        [Paragraph("Monthly CO2e", S["tbl_header"]),
         Paragraph("Annual CO2e", S["tbl_header"]),
         Paragraph("Monthly Energy", S["tbl_header"]),
         Paragraph("Region Intensity", S["tbl_header"])],
        [Paragraph(monthly_label, _co2_style("c1", _C_GREEN_DARK)),
         Paragraph(annual_label,  _co2_style("c2", _C_GREEN_DARK)),
         Paragraph(kwh_label,     _co2_style("c3", C_BLUE)),
         Paragraph(f"{carbon.primary_intensity:.3f}\nkgCO2e/kWh",
                   ParagraphStyle("c4", fontName="Helvetica-Bold", fontSize=13,
                                  leading=17, textColor=C_GREY, alignment=TA_CENTER))],
        [Paragraph(f"Region: {carbon.primary_region}", S["muted"]),
         Paragraph("12-month projection", S["muted"]),
         Paragraph(f"{carbon.total_monthly_kwh * 12:,.0f} kWh/year", S["muted"]),
         Paragraph("Grid emission factor", S["muted"])],
    ]
    kpi_col = CONTENT_W / 4
    kpi_ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("BACKGROUND",    (0, 1), (-1, 1),  _C_GREEN_PALE),
        ("BACKGROUND",    (0, 2), (-1, 2),  C_GREY_LT),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
    ])
    elems.append(Table(kpi_data, colWidths=[kpi_col] * 4, style=kpi_ts))
    elems.append(Spacer(1, 5 * mm))

    # ── Waste impact (if applicable) ──────────────────────────────────────────
    if carbon.waste_applied:
        elems.append(Paragraph(
            f"⚠  <b>Over-provisioning detected (+{carbon.waste_co2e_kg:,.1f} kg CO2e/month).</b>  "
            f"Failing WAF-COST controls (rightsizing, lifecycle, FinOps review) indicate "
            f"unoptimised workloads consuming an estimated {int((carbon.waste_multiplier - 1) * 100)}% "
            f"more energy than necessary. Fixing these controls could eliminate "
            f"<b>{carbon.savings_if_optimised_kg:,.1f} kg CO2e/month</b> of waste.",
            ParagraphStyle("waste_warn", fontName="Helvetica", fontSize=9, leading=13,
                           textColor=C_ORANGE, borderPadding=(4, 8, 4, 8),
                           backColor=C_ORANGE_LT),
        ))
        elems.append(Spacer(1, 4 * mm))

    # ── Real-world equivalences ───────────────────────────────────────────────
    elems.append(Paragraph("Monthly footprint — real-world equivalences", S["h3"]))
    elems.append(Spacer(1, 2 * mm))

    eq_data = [
        [Paragraph("🚗  Car miles", S["tbl_header"]),
         Paragraph("🌳  Trees to offset", S["tbl_header"]),
         Paragraph("📱  Phone charges", S["tbl_header"]),
         Paragraph("✈️  Flight hours", S["tbl_header"])],
        [Paragraph(f"{carbon.eq_car_miles:,.0f}",
                   _co2_style("eq1", C_RED if carbon.eq_car_miles > 500 else C_DARK)),
         Paragraph(f"{carbon.eq_trees_needed:,.1f}",
                   _co2_style("eq2", _C_GREEN_DARK)),
         Paragraph(f"{carbon.eq_smartphone_charges:,.0f}",
                   _co2_style("eq3", C_DARK)),
         Paragraph(f"{carbon.eq_flight_hours:,.1f}",
                   _co2_style("eq4", C_DARK))],
        [Paragraph("passenger vehicle", S["muted"]),
         Paragraph("per year (annual footprint)", S["muted"]),
         Paragraph("smartphone charges", S["muted"]),
         Paragraph("economy class", S["muted"])],
    ]
    eq_ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  _C_GREEN_DARK),
        ("BACKGROUND",    (0, 1), (-1, 1),  C_GREY_LT),
        ("BACKGROUND",    (0, 2), (-1, 2),  C_WHITE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
    ])
    elems.append(Table(eq_data, colWidths=[kpi_col] * 4, style=eq_ts))
    elems.append(Spacer(1, 5 * mm))

    # ── Region comparison bar ─────────────────────────────────────────────────
    if carbon.savings_vs_greenest_kg > 0.5:
        elems.append(Paragraph("Region optimisation opportunity", S["h3"]))
        elems.append(Spacer(1, 2 * mm))
        elems.append(Paragraph(
            f"Deploying to <b>{carbon.greenest_region_label}</b> "
            f"(grid intensity {carbon.greenest_intensity:.3f} kgCO2e/kWh) "
            f"instead of <b>{carbon.primary_region}</b> "
            f"({carbon.primary_intensity:.3f} kgCO2e/kWh) "
            f"would reduce monthly emissions by "
            f"<b>{carbon.savings_vs_greenest_kg:,.1f} kg CO2e "
            f"({carbon.savings_vs_greenest_kg / carbon.total_monthly_co2e_kg * 100:.0f}%)</b>.",
            S["body"],
        ))
        elems.append(Spacer(1, 3 * mm))

        # Simple horizontal comparison table
        curr_pct = 100.0
        green_pct = (carbon.greenest_monthly_co2e_kg / carbon.total_monthly_co2e_kg * 100
                     if carbon.total_monthly_co2e_kg > 0 else 0)
        reg_data = [
            [Paragraph("Region", S["tbl_header_left"]),
             Paragraph("Monthly CO2e", S["tbl_header"]),
             Paragraph("Intensity", S["tbl_header"]),
             Paragraph("vs. Current", S["tbl_header"])],
            [Paragraph(f"<b>{carbon.primary_region}</b> (current)", S["body_sm"]),
             Paragraph(f"{carbon.total_monthly_co2e_kg:,.1f} kg", S["body_sm"]),
             Paragraph(f"{carbon.primary_intensity:.3f}", S["body_sm"]),
             Paragraph("—", S["body_sm"])],
            [Paragraph(f"{carbon.greenest_region_label}", S["body_sm"]),
             Paragraph(f"{carbon.greenest_monthly_co2e_kg:,.1f} kg",
                       ParagraphStyle("grn", fontName="Helvetica-Bold", fontSize=9,
                                      leading=12, textColor=_C_GREEN_DARK)),
             Paragraph(f"{carbon.greenest_intensity:.3f}", S["body_sm"]),
             Paragraph(f"−{curr_pct - green_pct:.0f}%",
                       ParagraphStyle("grn2", fontName="Helvetica-Bold", fontSize=9,
                                      leading=12, textColor=_C_GREEN_DARK,
                                      alignment=TA_CENTER))],
        ]
        reg_ts = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, _C_GREEN_PALE]),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("LEADING",       (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ])
        reg_col_ws = [CONTENT_W * 0.38, CONTENT_W * 0.22, CONTENT_W * 0.20, CONTENT_W * 0.20]
        elems.append(Table(reg_data, colWidths=reg_col_ws, style=reg_ts))
        elems.append(Spacer(1, 5 * mm))

    # ── Per-resource-type breakdown ───────────────────────────────────────────
    if carbon.breakdown:
        elems.append(Paragraph("Footprint by resource type", S["h3"]))
        elems.append(Spacer(1, 2 * mm))

        top_n = carbon.breakdown[:15]   # top 15 by CO2e
        hdr = ["Resource Type", "Count", "W / instance", "kWh / month", "kgCO2e / month"]
        col_ws = [CONTENT_W * 0.38, CONTENT_W * 0.08, CONTENT_W * 0.14,
                  CONTENT_W * 0.18, CONTENT_W * 0.22]
        rows: list[list] = [[
            Paragraph(h, S["tbl_header_left"] if i == 0 else S["tbl_header"])
            for i, h in enumerate(hdr)
        ]]
        total_co2 = carbon.total_monthly_co2e_kg or 1.0
        for rf in top_n:
            pct = rf.monthly_co2e_kg / total_co2 * 100
            bar = "█" * max(1, int(pct / 5))   # simple ASCII bar
            rows.append([
                Paragraph(rf.resource_type, S["body_sm"]),
                Paragraph(str(rf.count), S["body_sm"]),
                Paragraph(f"{rf.watts_each:.0f} W", S["body_sm"]),
                Paragraph(f"{rf.monthly_kwh:,.1f}", S["body_sm"]),
                Paragraph(f"{rf.monthly_co2e_kg:,.2f}  <font color='#059669' size='7'>{bar} {pct:.0f}%</font>",
                          S["body_sm"]),
            ])
        if len(carbon.breakdown) > 15:
            rows.append([Paragraph(f"… and {len(carbon.breakdown) - 15} more types",
                                   S["muted"]), *[""] * 4])

        br_ts = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (1, 0), (-1, 0),  "CENTER"),
            ("ALIGN",         (1, 1), (-1, -1), "CENTER"),
        ])
        elems.append(Table(rows, colWidths=col_ws, style=br_ts))

    return elems


# ── Blast Radius section ──────────────────────────────────────────────────────

_BR_IMPACT_COLORS: dict[str, tuple] = {
    "CRITICAL": (C_RED,    C_RED_LT),
    "HIGH":     (C_ORANGE, C_ORANGE_LT),
    "MEDIUM":   (C_YELLOW, C_YELLOW_LT),
    "LOW":      (C_GREY,   C_GREY_LT),
}


def _blast_radius_section(br_result: "BlastResult", S: dict) -> list:
    """Build the Blast Radius Analysis section for the PDF report."""
    from wafpass.blast_radius import BlastResult  # local import – optional feature

    if not br_result.roots:
        return []

    elems: list = [
        *_section_header("Blast Radius Analysis", S),
        Paragraph(
            "Resources that failed one or more controls and the downstream resources "
            "that reference them and are therefore indirectly exposed. "
            "Hop 0 = root cause; Hop 1 = directly dependent (HIGH); "
            "Hop 2 = secondary (MEDIUM); Hop 3+ = residual (LOW).",
            S["muted"],
        ),
        Spacer(1, 3 * mm),
    ]

    # ── Summary KPI strip ─────────────────────────────────────────────────────
    kpi_data = [
        [
            Paragraph("Root-cause resources", S["tbl_header"]),
            Paragraph("Downstream affected", S["tbl_header"]),
            Paragraph("Total impacted", S["tbl_header"]),
        ],
        [
            Paragraph(str(len(br_result.roots)), ParagraphStyle(
                "br_kpi", fontName="Helvetica-Bold", fontSize=20,
                leading=24, textColor=C_RED, alignment=TA_CENTER)),
            Paragraph(str(len(br_result.affected)), ParagraphStyle(
                "br_kpi2", fontName="Helvetica-Bold", fontSize=20,
                leading=24, textColor=C_ORANGE, alignment=TA_CENTER)),
            Paragraph(str(br_result.total_affected), ParagraphStyle(
                "br_kpi3", fontName="Helvetica-Bold", fontSize=20,
                leading=24, textColor=C_NAVY, alignment=TA_CENTER)),
        ],
    ]
    kpi_col_w = CONTENT_W / 3
    kpi_ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("BACKGROUND",    (0, 1), (-1, 1),  C_GREY_LT),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
    ])
    elems.append(Table(kpi_data, colWidths=[kpi_col_w] * 3, style=kpi_ts))
    elems.append(Spacer(1, 5 * mm))

    # ── Root cause table ──────────────────────────────────────────────────────
    elems.append(Paragraph("Root-cause resources (Hop 0)", S["h3"]))
    elems.append(Spacer(1, 2 * mm))

    root_hdr = ["Resource", "Severity", "Impact", "Failed Controls"]
    root_col_ws = [
        CONTENT_W * 0.35,
        CONTENT_W * 0.10,
        CONTENT_W * 0.10,
        CONTENT_W * 0.45,
    ]
    root_rows: list[list] = [
        [Paragraph(h, S["tbl_header_left"] if i == 0 else S["tbl_header"])
         for i, h in enumerate(root_hdr)]
    ]

    for node in sorted(br_result.roots, key=lambda n: (
            -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(n.impact_label, 0),
            n.address)):
        sev = (node.failed_severity or "low").lower()
        fg, bg = _BR_IMPACT_COLORS.get(node.impact_label, (C_GREY, C_GREY_LT))
        sev_style = ParagraphStyle(
            f"br_sev_{sev}", fontName="Helvetica-Bold", fontSize=8,
            leading=11, textColor=fg, alignment=TA_CENTER)
        impact_style = ParagraphStyle(
            f"br_imp_{node.impact_label}", fontName="Helvetica-Bold", fontSize=8,
            leading=11, textColor=fg, alignment=TA_CENTER)
        ctrls = ", ".join(node.failed_controls) if node.failed_controls else "—"
        root_rows.append([
            Paragraph(f'<font size="8">{node.address}</font>', S["code"]),
            Paragraph(sev.upper(), sev_style),
            Paragraph(node.impact_label, impact_style),
            Paragraph(f'<font size="8">{ctrls}</font>', S["body_sm"]),
        ])

    root_ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (1, 0), (-1, 0),  "CENTER"),
        ("ALIGN",         (1, 1), (-1, -1), "CENTER"),
        ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
    ])
    elems.append(Table(root_rows, colWidths=root_col_ws, style=root_ts))

    # ── Downstream affected table ─────────────────────────────────────────────
    if br_result.affected:
        elems.append(Spacer(1, 5 * mm))
        elems.append(Paragraph("Downstream affected resources", S["h3"]))
        elems.append(Spacer(1, 2 * mm))

        aff_hdr = ["Resource", "Hop", "Impact", "Depends on"]
        aff_col_ws = [
            CONTENT_W * 0.35,
            CONTENT_W * 0.06,
            CONTENT_W * 0.10,
            CONTENT_W * 0.49,
        ]
        aff_rows: list[list] = [
            [Paragraph(h, S["tbl_header_left"] if i == 0 else S["tbl_header"])
             for i, h in enumerate(aff_hdr)]
        ]

        for node in br_result.affected:
            fg, _bg = _BR_IMPACT_COLORS.get(node.impact_label, (C_GREY, C_GREY_LT))
            impact_style = ParagraphStyle(
                f"br_aff_{node.impact_label}_{node.address[:8]}", fontName="Helvetica-Bold",
                fontSize=8, leading=11, textColor=fg, alignment=TA_CENTER)
            parents_str = ", ".join(node.parents) if node.parents else "—"
            aff_rows.append([
                Paragraph(f'<font size="8">{node.address}</font>', S["code"]),
                Paragraph(str(node.hop), S["body_sm"]),
                Paragraph(node.impact_label, impact_style),
                Paragraph(f'<font size="8">{parents_str}</font>', S["body_sm"]),
            ])

        aff_ts = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (1, 0), (-1, 0),  "CENTER"),
            ("ALIGN",         (1, 1), (-1, -1), "CENTER"),
            ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
            ("ALIGN",         (3, 1), (3, -1),  "LEFT"),
        ])
        elems.append(Table(aff_rows, colWidths=aff_col_ws, style=aff_ts))

    return elems


# ── Hardcoded Secrets section ─────────────────────────────────────────────────

_SECRET_SEV_COLORS: dict[str, tuple] = {
    "critical": (C_RED,    C_RED_LT),
    "high":     (C_ORANGE, C_ORANGE_LT),
    "medium":   (C_YELLOW, C_YELLOW_LT),
}


def _secrets_section(findings: list, S: dict) -> list:
    """Build the Hardcoded Secrets section for the PDF report."""
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]

    if not active and not suppressed:
        return []

    elems: list = [
        *_section_header("Hardcoded Secrets", S),
        Paragraph(
            "The following IaC source files contain hardcoded credential material "
            "(passwords, API keys, tokens, private keys, or connection strings). "
            "Hardcoded secrets committed to version control persist in git history "
            "indefinitely and represent a critical attack surface. "
            "All findings must be remediated before deployment.",
            S["muted"],
        ),
        Spacer(1, 3 * mm),
    ]

    # ── KPI strip ─────────────────────────────────────────────────────────────
    n_crit = sum(1 for f in active if f.severity == "critical")
    n_high = sum(1 for f in active if f.severity == "high")
    n_med  = sum(1 for f in active if f.severity == "medium")
    kpi_data = [
        [
            Paragraph("Critical", S["tbl_header"]),
            Paragraph("High", S["tbl_header"]),
            Paragraph("Medium", S["tbl_header"]),
            Paragraph("Suppressed", S["tbl_header"]),
        ],
        [
            Paragraph(str(n_crit), ParagraphStyle("sec_k1", fontName="Helvetica-Bold",
                fontSize=18, leading=22, textColor=C_RED, alignment=TA_CENTER)),
            Paragraph(str(n_high), ParagraphStyle("sec_k2", fontName="Helvetica-Bold",
                fontSize=18, leading=22, textColor=C_ORANGE, alignment=TA_CENTER)),
            Paragraph(str(n_med), ParagraphStyle("sec_k3", fontName="Helvetica-Bold",
                fontSize=18, leading=22, textColor=C_YELLOW, alignment=TA_CENTER)),
            Paragraph(str(len(suppressed)), ParagraphStyle("sec_k4", fontName="Helvetica-Bold",
                fontSize=18, leading=22, textColor=C_GREY, alignment=TA_CENTER)),
        ],
    ]
    kpi_col_w = CONTENT_W / 4
    kpi_ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("BACKGROUND",    (0, 1), (-1, 1),  C_GREY_LT),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
    ])
    elems.append(Table(kpi_data, colWidths=[kpi_col_w] * 4, style=kpi_ts))
    elems.append(Spacer(1, 5 * mm))

    # ── Findings table ────────────────────────────────────────────────────────
    if active:
        hdr = ["Severity", "File : Line", "Finding", "Attribute", "Value (masked)"]
        col_ws = [
            CONTENT_W * 0.09,
            CONTENT_W * 0.28,
            CONTENT_W * 0.22,
            CONTENT_W * 0.17,
            CONTENT_W * 0.24,
        ]
        rows: list[list] = [
            [Paragraph(h, S["tbl_header_left"] if i == 1 else S["tbl_header"])
             for i, h in enumerate(hdr)]
        ]

        for f in active:
            fg, bg = _SECRET_SEV_COLORS.get(f.severity, (C_GREY, C_GREY_LT))
            sev_style = ParagraphStyle(
                f"sec_{f.severity}", fontName="Helvetica-Bold", fontSize=8,
                leading=11, textColor=fg, alignment=TA_CENTER)
            rows.append([
                Paragraph(f.severity.upper(), sev_style),
                Paragraph(f'<font size="7">{f.file}:{f.line_no}</font>', S["code"]),
                Paragraph(f.pattern_name, S["body_sm"]),
                Paragraph(f.matched_key or "—", S["body_sm"]),
                Paragraph(f'<font name="Courier">{f.masked_value}</font>', S["body_sm"]),
            ])

        ts = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (0, 1), (0, -1),  "CENTER"),
        ])
        elems.append(Table(rows, colWidths=col_ws, style=ts))
        elems.append(Spacer(1, 5 * mm))

    # ── Remediation guidance box ───────────────────────────────────────────────
    from wafpass.secret_scanner import REMEDIATION_GUIDANCE
    guide_rows = []
    for line in REMEDIATION_GUIDANCE.splitlines():
        guide_rows.append(Paragraph(
            line if line.strip() else "&nbsp;",
            S["code"] if line.startswith("  ") else S["body_sm"],
        ))
    elems.append(Table(
        [[col] for col in guide_rows],
        colWidths=[CONTENT_W],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_LT),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_ORANGE),
        ]),
    ))

    return elems


# ── Risk Acceptance Register (one-pager) ─────────────────────────────────────

def _risk_acceptance_section(report: Report, S: dict, generated_at: str) -> list:
    """Standalone Risk Acceptance Register page.

    Renders a printable register of all intentionally waived controls, suitable
    for sign-off by a CISO or Risk Owner.  Each entry shows the control ID,
    title, pillar, severity, justification, expiry date, and current status.
    """
    from datetime import date as _date

    waived = [cr for cr in report.results if cr.status == "WAIVED"]
    if not waived:
        return []

    today = _date.today()
    elems = [*_section_header("Risk Acceptance Register", S)]

    # ── Summary banner ──────────────────────────────────────────────────────
    active     = sum(1 for cr in waived if not (cr.waived_expires and cr.waived_expires < today))
    expired    = sum(1 for cr in waived if cr.waived_expires and cr.waived_expires < today)
    permanent  = sum(1 for cr in waived if not cr.waived_expires)
    expiring_soon = sum(
        1 for cr in waived
        if cr.waived_expires and not (cr.waived_expires < today)
        and (cr.waived_expires - today).days <= 30
    )

    intro = (
        "This register records all WAF++ controls for which the organisation has made a "
        "conscious, documented decision to accept residual risk.  Each waiver requires a "
        "written justification and an optional review date.  Waivers without an expiry date "
        "are treated as permanent until explicitly revoked."
    )
    elems.append(Paragraph(intro, S["muted"]))
    elems.append(Spacer(1, 4 * mm))

    # KPI summary row
    kpi_data = [
        [
            Paragraph(str(len(waived)), S["kpi_number"]),
            Paragraph(str(active),      S["kpi_number"]),
            Paragraph(str(expired),     S["kpi_number"]),
            Paragraph(str(permanent),   S["kpi_number"]),
        ],
        [
            Paragraph("Total Waivers",   S["kpi_label"]),
            Paragraph("Active",          S["kpi_label"]),
            Paragraph("Expired",         S["kpi_label"]),
            Paragraph("Permanent",       S["kpi_label"]),
        ],
    ]
    kpi_colors = [C_PURPLE, C_GREEN, C_RED, C_GREY]
    kpi_w = CONTENT_W / 4
    kpi_ts = TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
    ])
    for col_idx, col_color in enumerate(kpi_colors):
        kpi_ts.add("BACKGROUND", (col_idx, 0), (col_idx, 1), col_color)
        kpi_ts.add("TEXTCOLOR",  (col_idx, 0), (col_idx, 1), C_WHITE)
    elems.append(Table(kpi_data, colWidths=[kpi_w] * 4, style=kpi_ts))

    if expiring_soon:
        elems.append(Spacer(1, 3 * mm))
        elems.append(Paragraph(
            f"⚠  {expiring_soon} waiver(s) expire within 30 days — review required.",
            S["alert_text"],
        ))

    elems.append(Spacer(1, 5 * mm))

    # ── Main register table ──────────────────────────────────────────────────
    sev_fg = {
        "critical": C_RED, "high": C_ORANGE, "medium": C_YELLOW, "low": C_BLUE,
    }

    header = ["Control", "Title", "Pillar", "Sev.", "Justification", "Expires", "Status"]
    col_widths = [
        2.6 * cm,          # Control ID
        CONTENT_W * 0.22,  # Title
        2.0 * cm,          # Pillar
        1.4 * cm,          # Severity
        CONTENT_W * 0.30,  # Justification
        2.0 * cm,          # Expires
        1.8 * cm,          # Status
    ]

    def _row_status(cr: "ControlResult") -> tuple[str, colors.Color]:
        if cr.waived_expires and cr.waived_expires < today:
            return "EXPIRED", C_RED
        if cr.waived_expires:
            days = (cr.waived_expires - today).days
            if days <= 30:
                return f"≤30d", C_ORANGE
            return "ACTIVE", C_GREEN
        return "PERM.", C_GREY

    rows: list = [
        [Paragraph(h, S["tbl_header"]) for h in header]
    ]
    row_status_colors: list[colors.Color] = []

    for cr in waived:
        exp_str = str(cr.waived_expires) if cr.waived_expires else "—"
        status_label, status_color = _row_status(cr)
        row_status_colors.append(status_color)
        pillar = cr.control.pillar.capitalize()[:6]
        sev    = cr.control.severity[:4].capitalize()
        reason = (cr.waived_reason or "")
        rows.append([
            Paragraph(cr.control.id, S["body_sm"]),
            Paragraph(cr.control.title[:60] + ("…" if len(cr.control.title) > 60 else ""), S["body_sm"]),
            Paragraph(pillar, S["body_sm"]),
            Paragraph(sev, ParagraphStyle(
                "sev_cell", parent=S["body_sm"],
                textColor=sev_fg.get(cr.control.severity.lower(), C_GREY),
                fontName="Helvetica-Bold",
            )),
            Paragraph(reason[:160] + ("…" if len(reason) > 160 else ""), S["body_sm"]),
            Paragraph(exp_str, S["body_sm"]),
            Paragraph(status_label, ParagraphStyle(
                "status_cell", parent=S["body_sm"],
                textColor=status_color, fontName="Helvetica-Bold",
            )),
        ])

    ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7),
        ("LEADING",       (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_PURPLE),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_PURPLE_LT]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])
    elems.append(Table(rows, colWidths=col_widths, style=ts, repeatRows=1))

    # ── Sign-off block ───────────────────────────────────────────────────────
    elems.append(Spacer(1, 8 * mm))
    elems.append(_hr(C_BORDER, 0.5))
    elems.append(Spacer(1, 4 * mm))
    elems.append(Paragraph("Sign-off &amp; Approval", S["h3"]))
    elems.append(Spacer(1, 3 * mm))
    elems.append(Paragraph(
        "This Risk Acceptance Register was generated automatically from the "
        f"<b>risk_acceptance.yml</b> waiver file as part of a WAF++ PASS scan on "
        f"<b>{generated_at}</b>.  The Risk Owner below confirms that each waiver "
        "reflects a current, informed decision and that compensating controls are in place.",
        S["muted"],
    ))
    elems.append(Spacer(1, 6 * mm))

    signoff_rows = [
        ["Risk Owner / CISO", "___________________________________________", "Date", "________________"],
        ["Approved by",       "___________________________________________", "Date", "________________"],
    ]
    signoff_ts = TableStyle([
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("LEADING",       (0, 0), (-1, -1), 14),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",     (0, 0), (0, -1),  C_GREY),
        ("TEXTCOLOR",     (2, 0), (2, -1),  C_GREY),
    ])
    signoff_widths = [3.5 * cm, CONTENT_W * 0.45, 1.5 * cm, CONTENT_W * 0.25]
    elems.append(Table(
        [[Paragraph(c, S["muted"] if i % 2 == 0 else S["body"]) for i, c in enumerate(row)]
         for row in signoff_rows],
        colWidths=signoff_widths,
        style=signoff_ts,
    ))

    return elems


# ── Validation certificate ────────────────────────────────────────────────────

def generate_validation_certificate(
    envelope: ValidationEnvelopeSchema,
    output_path: Path,
) -> None:
    """Render a one-page PDF certificate for a WAF++ validation envelope.

    The certificate is a standalone, printable proof of validation. It includes
    the run metadata, the cryptographic validation ID, the certificate chain
    fingerprints, and instructions for independent verification.
    """
    from cryptography import x509

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    result_dict = envelope.result.model_dump() if envelope.result else {}
    sv = envelope.server_validation
    status = envelope.status
    is_official = status == "official"

    status_fg = C_GREEN if is_official else C_YELLOW
    status_bg = C_GREEN_LT if is_official else C_YELLOW_LT
    status_label = "OFFICIALLY VALIDATED" if is_official else "OFFLINE VALIDATION"

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    c = pdfcanvas.Canvas(str(output_path), pagesize=A4)

    # ── Full-page subtle background ─────────────────────────────────────────────
    c.setFillColor(colors.HexColor("#f8fafc"))
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # ── Top navy band with wordmark ────────────────────────────────────────────
    c.setFillColor(C_NAVY)
    c.rect(0, PAGE_H - 4.2 * cm, PAGE_W, 4.2 * cm, fill=1, stroke=0)
    _draw_logo(c, MARGIN, PAGE_H - 3.2 * cm, size=36)
    c.setFillColor(C_WHITE)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(MARGIN + 44, PAGE_H - 2.15 * cm, "WAF")
    w_waf = c.stringWidth("WAF", "Helvetica-Bold", 22)
    c.setFillColor(C_BLUE)
    c.drawString(MARGIN + 44 + w_waf, PAGE_H - 2.15 * cm, "++")
    c.setFillColor(colors.HexColor("#94a3b8"))
    c.setFont("Helvetica", 11)
    c.drawString(MARGIN + 44, PAGE_H - 2.75 * cm, "Official Validation Certificate")

    # ── Blue accent line ────────────────────────────────────────────────────────
    c.setStrokeColor(C_BLUE)
    c.setLineWidth(3)
    c.line(MARGIN, PAGE_H - 4.35 * cm, PAGE_W - MARGIN, PAGE_H - 4.35 * cm)

    # ── Status badge ────────────────────────────────────────────────────────────
    badge_w = 6.2 * cm
    badge_h = 1.4 * cm
    badge_x = (PAGE_W - badge_w) / 2
    badge_y = PAGE_H - 6.2 * cm
    c.setFillColor(status_bg)
    c.setStrokeColor(status_fg)
    c.setLineWidth(1.5)
    c.roundRect(badge_x, badge_y, badge_w, badge_h, 8, fill=1, stroke=1)
    c.setFillColor(status_fg)
    c.setFont("Helvetica-Bold", 14)
    label_w = c.stringWidth(status_label, "Helvetica-Bold", 14)
    c.drawString((PAGE_W - label_w) / 2, badge_y + 0.5 * cm, status_label)

    # ── Intro text ──────────────────────────────────────────────────────────────
    y = PAGE_H - 8.0 * cm
    c.setFillColor(C_DARK)
    c.setFont("Helvetica", 10)
    intro = (
        "This certificate attests that the WAF++ PASS run identified below was "
        "cryptographically signed by the organization and, for official validations, "
        "counter-signed by the WAF++ central validation authority. "
        "The certificate can be re-verified at any time using the public verification URL or the "
        "wafpass verify command."
    )
    text_obj = c.beginText(MARGIN, y)
    text_obj.setFont("Helvetica", 10)
    text_obj.setFillColor(C_DARK)
    for line in _wrap_text(intro, CONTENT_W, "Helvetica", 10, c):
        text_obj.textLine(line)
    c.drawText(text_obj)

    # ── Certificate metadata table ──────────────────────────────────────────────
    y = text_obj.getY() - 1.0 * cm
    metadata = [
        ["Validation ID", sv.validation_id if sv else "— (offline)"],
        ["Run hash", envelope.run_hash],
        ["Project", result_dict.get("project") or "—"],
        ["Branch", result_dict.get("branch") or "—"],
        ["Git SHA", result_dict.get("git_sha") or "—"],
        ["Score", f"{result_dict.get('score', '—')}%"],
        ["Status", status.upper()],
        ["Signed by", envelope.local_attestation.signer_kind],
        ["Signed at", envelope.local_attestation.signed_at],
        ["Validated at", sv.validated_at if sv else "—"],
    ]
    if sv and sv.expires_at:
        metadata.append(["Expires at", sv.expires_at])
    if sv and sv.verification_url:
        metadata.append(["Verification URL", sv.verification_url])
    if envelope.metadata:
        if envelope.metadata.get("organization"):
            metadata.append(["Organization", envelope.metadata["organization"]])
        if envelope.metadata.get("environment"):
            metadata.append(["Environment", envelope.metadata["environment"]])
        if envelope.metadata.get("validated_by"):
            metadata.append(["Validated by", envelope.metadata["validated_by"]])
        if envelope.metadata.get("notes"):
            metadata.append(["Notes", envelope.metadata["notes"]])

    S = _styles()
    rows = [
        [Paragraph(f'<font name="Helvetica-Bold" color="#{_hex(C_NAVY)}">{k}</font>', S["body"]),
         Paragraph(str(v), S["body"])]
        for k, v in metadata
    ]
    table = Table(rows, colWidths=[4.2 * cm, CONTENT_W - 4.2 * cm])
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("LEADING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_GREY_LT]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    table.wrapOn(c, CONTENT_W, PAGE_H)
    table.drawOn(c, MARGIN, y - table._height)

    y = y - table._height - 1.0 * cm

    # ── Certificate chain section ─────────────────────────────────────────────
    if sv and sv.certificate_chain:
        c.setFillColor(C_NAVY)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN, y, "Certificate Chain")
        y -= 0.6 * cm

        chain_rows = []
        for idx, cert_pem in enumerate(sv.certificate_chain):
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
                fingerprint = cert.fingerprint(hashlib.sha256()).hex()
                subject = cert.subject.rfc4514_string()
            except Exception:
                subject = "(could not parse certificate)"
                fingerprint = "—"
            position = "Server Intermediate" if idx == 0 else "WAF++ Root CA"
            chain_rows.append([
                Paragraph(f'<font name="Helvetica-Bold" color="#{_hex(C_NAVY)}">{position}</font>', S["body_sm"]),
                Paragraph(f'<font size="8" name="Courier">{fingerprint}</font>', S["body_sm"]),
                Paragraph(subject, S["body_sm"]),
            ])

        chain_table = Table(chain_rows, colWidths=[3.2 * cm, 7.8 * cm, CONTENT_W - 11.0 * cm])
        chain_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 11),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_GREY_LT]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        chain_table.wrapOn(c, CONTENT_W, PAGE_H)
        chain_table.drawOn(c, MARGIN, y - chain_table._height)
        y = y - chain_table._height - 1.0 * cm

    # ── Verification instructions ───────────────────────────────────────────────
    c.setFillColor(C_NAVY)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN, y, "Independent Verification")
    y -= 0.6 * cm

    verify_text = (
        "Anyone can verify this validation by running:\n\n"
        "  wafpass verify <envelope.json>\n\n"
        "For official validations, the server status can also be checked online at the "
        "Verification URL shown above. The local attestation proves the run result has not "
        "been altered since it was signed; the server countersignature proves the WAF++ "
        "authority reviewed and recorded the validation."
    )
    if not is_official:
        verify_text = (
            "This is an offline, self-signed validation. It proves the run result was signed by "
            "the organization's private key, but it has not yet been countersigned by WAF++. "
            "Run 'wafpass validate upgrade --envelope <file>' once internet access is available "
            "to convert it to an official certificate."
        )

    text_obj = c.beginText(MARGIN, y)
    text_obj.setFont("Helvetica", 9)
    text_obj.setFillColor(C_DARK)
    for line in verify_text.splitlines():
        if line.startswith("  wafpass"):
            text_obj.setFont("Courier", 9)
            text_obj.textLine(line)
            text_obj.setFont("Helvetica", 9)
        else:
            for wrapped in _wrap_text(line, CONTENT_W, "Helvetica", 9, c):
                text_obj.textLine(wrapped)
    c.drawText(text_obj)

    # ── Bottom footer ───────────────────────────────────────────────────────────
    footer_y = MARGIN - 0.6 * cm
    c.setStrokeColor(C_BORDER)
    c.setLineWidth(0.5)
    c.line(MARGIN, footer_y + 0.8 * cm, PAGE_W - MARGIN, footer_y + 0.8 * cm)
    c.setFillColor(C_GREY)
    c.setFont("Helvetica", 8)
    c.drawString(MARGIN, footer_y, f"Generated {generated_at} · WAF++ PASS v{__version__}")
    c.drawRightString(PAGE_W - MARGIN, footer_y, "waf2p.dev")

    c.showPage()
    c.save()


def _wrap_text(text: str, max_width: float, font_name: str, font_size: float, canvas: pdfcanvas.Canvas) -> list[str]:
    """Wrap *text* into lines that fit within *max_width* points."""
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        test = f"{current} {word}"
        if canvas.stringWidth(test, font_name, font_size) <= max_width:
            current = test
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_pdf(
    report: Report,
    output_path: Path,
    baseline: dict | None = None,
    diff: dict | None = None,
    blast_radius_result: "BlastResult | None" = None,
    secret_findings: list | None = None,
    carbon_result: "CarbonResult | None" = None,
    waivers: list | None = None,
) -> None:
    """Generate a structured, audience-segmented PDF report.

    The report is divided into five parts plus an appendix, each introduced by
    a full-page divider that identifies the intended audience:

    PART I   — Security Alerts       (DevSecOps, Engineering leads)
    PART II  — Executive Briefing    (C-Suite, Board)
    PART III — Risk & Sustainability (CISO, CTO, CFO, Sustainability team)
    PART IV  — Technical Deep Dive   (Architects, Senior engineers)
    PART V   — Remediation           (Engineering teams)
    Appendix — Compliance evidence + Risk Acceptance Register (Auditors, GRC)
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    S = _styles()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cover_on_page  = _CoverCanvas(generated_at)
    normal_on_page = _PageCanvas(generated_at)

    content_frame = Frame(
        MARGIN, MARGIN,
        CONTENT_W, PAGE_H - 2 * MARGIN,
        leftPadding=0, rightPadding=0,
        topPadding=8 * mm, bottomPadding=4 * mm,
    )

    cover_template  = PageTemplate(id="cover",  frames=[content_frame], onPage=cover_on_page)
    normal_template = PageTemplate(id="normal", frames=[content_frame], onPage=normal_on_page)

    # Full-page, zero-margin frame for part-divider pages — no header/footer chrome
    def _blank_canvas(canvas, doc):  # noqa: ARG001
        pass

    divider_frame = Frame(
        0, 0, PAGE_W, PAGE_H,
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )
    divider_template = PageTemplate(id="divider", frames=[divider_frame], onPage=_blank_canvas)

    doc = _WAFDocTemplate(
        str(output_path),
        pagesize=A4,
        pageTemplates=[cover_template, normal_template, divider_template],
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
        title="WAF++ Architecture Review Report",
        author=f"WAF++ PASS v{__version__}",
        subject="Infrastructure Security & Compliance Assessment",
        creator="waf2p.dev",
    )

    story: list = []

    # ══════════════════════════════════════════════════════════════════════════
    # Cover & TOC
    # ══════════════════════════════════════════════════════════════════════════
    story += _cover_content(report, S, generated_at)
    story += [NextPageTemplate("normal"), PageBreak()]
    story += _toc_section(S)

    # ══════════════════════════════════════════════════════════════════════════
    # PART I — SECURITY ALERTS
    # Audience: DevSecOps, Engineering Leads, Security Team
    # ══════════════════════════════════════════════════════════════════════════
    _has_sec_alerts = bool(secret_findings)
    if _has_sec_alerts:
        story += _part_divider(
            "I", "Security Alerts",
            "Critical pre-deployment security gates requiring immediate action",
            "DevSecOps · Engineering Leads · Security Team",
        )

        sec_elems = _secrets_section(secret_findings, S)
        if sec_elems:
            story += [PageBreak()]
            story += sec_elems

    # ══════════════════════════════════════════════════════════════════════════
    # PART II — EXECUTIVE BRIEFING
    # Audience: C-Suite, Board Members, Programme Sponsors
    # ══════════════════════════════════════════════════════════════════════════
    story += _part_divider(
        "II", "Executive Briefing",
        "Risk posture, trend analysis, and strategic decision context",
        "C-Suite · Board Members · Programme Sponsors",
    )

    story += [PageBreak()]
    story += _executive_decision_brief(report, S, baseline=baseline)

    if diff is not None:
        story += [PageBreak()]
        story += _changes_section(diff, S)

    # ══════════════════════════════════════════════════════════════════════════
    # PART III — RISK & SUSTAINABILITY
    # Audience: CISO, CTO, CFO, Sustainability / ESG team
    # ══════════════════════════════════════════════════════════════════════════
    story += _part_divider(
        "III", "Risk & Sustainability",
        "Financial exposure, carbon footprint, and data sovereignty",
        "CISO · CTO · CFO · Sustainability / ESG Team",
    )

    story += [PageBreak()]
    story += _risk_financial_section(report, S, baseline=baseline)

    if carbon_result is not None:
        story += [PageBreak()]
        story += _carbon_section(carbon_result, S)

    story += [PageBreak()]
    story += _data_geography_section(report, S)

    # ══════════════════════════════════════════════════════════════════════════
    # PART IV — TECHNICAL DEEP DIVE
    # Audience: Architects, Senior Engineers, Platform Team
    # ══════════════════════════════════════════════════════════════════════════
    story += _part_divider(
        "IV", "Technical Deep Dive",
        "Root causes, blast radius, and regulatory control mapping",
        "Architects · Senior Engineers · Platform Team",
    )

    root_cause_elems = _root_cause_section(report, S)
    if root_cause_elems:
        story += [PageBreak()]
        story += root_cause_elems

    if blast_radius_result is not None:
        br_elems = _blast_radius_section(blast_radius_result, S)
        if br_elems:
            story += [PageBreak()]
            story += br_elems

    story += [PageBreak()]
    story += _executive_summary(report, S)

    reg_elems = _regulatory_alignment(report, S)
    if reg_elems:
        story += [PageBreak()]
        story += reg_elems

    # ══════════════════════════════════════════════════════════════════════════
    # PART V — REMEDIATION
    # Audience: Engineering Teams, DevOps, Cloud Ops
    # ══════════════════════════════════════════════════════════════════════════
    story += _part_divider(
        "V", "Remediation",
        "Prioritised roadmap and per-control action items",
        "Engineering Teams · DevOps · Cloud Operations",
    )

    roadmap_elems = _remediation_roadmap_section(report, S)
    if roadmap_elems:
        story += [PageBreak()]
        story += roadmap_elems

    story += [PageBreak()]
    story += _findings_section(report, S)

    # ══════════════════════════════════════════════════════════════════════════
    # APPENDIX — Compliance Evidence
    # Audience: Auditors, GRC, Legal
    # ══════════════════════════════════════════════════════════════════════════
    story += _part_divider(
        "APP", "Appendix",
        "Controls inventory, passed checks, and compliance evidence",
        "Auditors · GRC · Legal · Compliance Team",
    )

    story += [PageBreak()]
    story += _controls_overview(report, S)

    story += [PageBreak()]
    story += _passed_section(report, S)

    risk_acc_elems = _risk_acceptance_section(report, S, generated_at)
    if risk_acc_elems:
        story += [PageBreak()]
        story += risk_acc_elems

    # multiBuild runs two passes so the TableOfContents can resolve page numbers
    doc.multiBuild(story)
