"""Values stored on the registers."""

from enum import Enum


class FrameworkId(str, Enum):
    """Saudi-first packs loaded as content, not as a separate engine."""

    NCA_ECC = "nca-ecc"
    SAMA_CSF = "sama-csf"
    KSA_PDPL = "ksa-pdpl"


class RiskTrigger(str, Enum):
    PROJECT = "project"
    CHANGE = "change"
    OUTSOURCING = "outsourcing"
    NEW_PRODUCT = "new_product"
    PERIODIC = "periodic"


class RiskResponse(str, Enum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class ImplementationStatus(str, Enum):
    NOT_STARTED = "not_started"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"


class SupplierDecision(str, Enum):
    PROCEED = "proceed"
    PROCEED_WITH_CONDITIONS = "proceed_with_conditions"
    STOP = "stop"
