from grc_app.catalog import STARTER_CONTROLS, controls_for
from grc_app.choices import FrameworkId


def test_starter_catalog_covers_the_saudi_packs() -> None:
    frameworks = {control.framework for control in STARTER_CONTROLS}
    assert frameworks == set(FrameworkId)
    assert [control.control_id for control in controls_for(FrameworkId.NCA_ECC)] == [
        "1-5-1",
        "1-5-2",
    ]
    assert controls_for(FrameworkId.KSA_PDPL)[0].control_id == "article-25"
