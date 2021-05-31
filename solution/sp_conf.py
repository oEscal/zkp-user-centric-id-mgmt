from saml2 import BINDING_HTTP_POST
from saml2.saml import NAME_FORMAT_URI

BASE = "http://127.0.0.1:8081"

CONFIG = {
    "entityid": BASE,
    "description": "Example SP",
    "service": {
        "sp": {
            "want_response_signed": True,
            "authn_requests_signed": True,
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/identity" % BASE, BINDING_HTTP_POST)
                ],
            },
            "requested_attributes": [
                {
                    'name': 'username',
                    'friendly_name': "username",
                    "required": True
                },
            ],
            "required_attributes": [
                'username'
            ]
        },
    },
    'cert_file': "sp_certificate/server.crt",
    "name_form": NAME_FORMAT_URI,
}
