import os

WEBAUTHN_RP_ID = os.environ.get(
    "WEBAUTHN_RP_ID",
    "vicky-earn-frontend.vercel.app"
)

WEBAUTHN_RP_NAME = os.environ.get(
    "WEBAUTHN_RP_NAME",
    "Vicky Earn"
)

WEBAUTHN_ORIGIN = os.environ.get(
    "WEBAUTHN_ORIGIN",
    "https://vicky-earn-frontend.vercel.app"
)

ADMIN_WEBAUTHN_RP_ID = os.environ.get(
    "ADMIN_WEBAUTHN_RP_ID",
    "vicky-earn-admin.vercel.app"
)

ADMIN_WEBAUTHN_RP_NAME = os.environ.get(
    "ADMIN_WEBAUTHN_RP_NAME",
    "Vicky Earn Admin"
)

ADMIN_WEBAUTHN_ORIGIN = os.environ.get(
    "ADMIN_WEBAUTHN_ORIGIN",
    "https://vicky-earn-admin.vercel.app"
)
