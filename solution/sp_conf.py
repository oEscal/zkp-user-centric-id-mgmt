from saml2.entity_category.edugain import COC
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.saml import NAME_FORMAT_URI

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None


if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin","/usr/local/bin"])
else:
    xmlsec_path = '/usr/local/bin/xmlsec1'

# Make sure the same port number appear in service_conf.py
BASE = "http://127.0.0.1:8081"

CONFIG = {
    "entityid": BASE,
    "description": "Example SP",
    "service": {
        "sp": {
            "want_response_signed": False,
            "authn_requests_signed": False,
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
    "name_form": NAME_FORMAT_URI,
}
