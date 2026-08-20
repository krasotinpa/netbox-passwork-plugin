"""
Template contract of secrets_tab.html: the header buttons passwork.js toggles
by id depending on the Passwork auth state (issue #14).
"""

from django.template.loader import render_to_string


def test_header_renders_bind_and_auth_buttons():
    html = render_to_string(
        "netbox_passwork/secrets_tab.html",
        {"object_type": "device", "object_id": 1},
    )

    # "Bind secret" — visible by default, opens the picker
    assert 'id="pw-bind-btn"' in html
    assert "pwOpenPicker" in html

    # "Authenticate" — hidden by default, opens the login modal directly
    auth_btn = html.split('id="pw-auth-btn"')
    assert len(auth_btn) == 2, "pw-auth-btn must be rendered exactly once"
    auth_btn_tag = auth_btn[1].split(">")[0] + auth_btn[1].split("</button>")[0]
    assert "display:none" in auth_btn_tag
    assert "pwShowLoginModal()" in auth_btn_tag
    assert "Authenticate" in auth_btn_tag
