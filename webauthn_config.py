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
