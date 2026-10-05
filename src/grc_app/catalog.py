"""Starter control identifiers for the Saudi-first packs.

Each entry names what this workspace tracks. It is not a copy of NCA, SAMA, or
PDPL control text.
"""

from typing import NamedTuple

from grc_app.choices import FrameworkId


class ControlRef(NamedTuple):
    framework: FrameworkId
    control_id: str
    title: str
    tracks: str


STARTER_CONTROLS: tuple[ControlRef, ...] = (
    ControlRef(
        FrameworkId.NCA_ECC,
        "1-5-1",
        "Cybersecurity risk methodology",
        "How risks are identified, updated, and kept in the register.",
    ),
    ControlRef(
        FrameworkId.NCA_ECC,
        "1-5-2",
        "Cybersecurity risk register and treatment",
        "The risk register and the treatment plan for each risk.",
    ),
    ControlRef(
        FrameworkId.SAMA_CSF,
        "3.2.1",
        "Cyber security risk management",
        (
            "Identification, analysis, response, and monitoring, including "
            "project, change, outsourcing, and new-product triggers, plus "
            "owner acceptance and risk appetite."
        ),
    ),
    ControlRef(
        FrameworkId.KSA_PDPL,
        "article-25",
        "Personal data breach notification",
        (
            "Authority notice within 72 hours when an incident may harm personal "
            "data: time, circumstances, categories, counts, risks, measures, "
            "whether people were told, contacts, and advice."
        ),
    ),
)


def controls_for(framework: FrameworkId) -> list[ControlRef]:
    return [control for control in STARTER_CONTROLS if control.framework == framework]
