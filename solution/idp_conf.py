import os.path

from saml2 import BINDING_HTTP_REDIRECT, BINDING_URI
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

HOST = '127.0.0.1'
PORT = 8082

HTTPS = False

if HTTPS:
    BASE = "https://%s:%s" % (HOST, PORT)
else:
    BASE = "http://%s:%s" % (HOST, PORT)

CONFIG = {
    "entityid": BASE,
    "description": "My IDP",
    "valid_for": 168,
    "service": {
        "idp": {
            "name": "IAA IdP",
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/login" % BASE, BINDING_HTTP_REDIRECT),
                ],
            },
            "want_authn_requests_only_with_valid_cert": True,
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None, # means all I have
                    "name_form": NAME_FORMAT_URI
                },
            },
            "subject_data": "./idp.subject",
            "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT]
        },
    },
    "metadata": {
        "local": [full_path("sp.xml")],
    },
    'key_file': "idp_certificate/server.key",
    'cert_file': "idp_certificate/server.crt",
    "organization": {
        "display_name": "IAA Identiteter",
        "name": "IAA Identiteter",
    },
    "contact_person": [
        {
            "contact_type": "technical",
            "given_name": "Pedro",
            "sur_name": "Escaleira",
        }
    ]
}

# Authentication contexts

    #(r'verify?(.*)$', do_verify),

CAS_SERVER = "https://cas.umu.se"
CAS_VERIFY = "%s/verify_cas" % BASE
PWD_VERIFY = "%s/verify_pwd" % BASE

AUTHORIZATION = {
    "CAS" : {"ACR": "CAS", "WEIGHT": 1, "URL": CAS_VERIFY},
    "UserPassword" : {"ACR": "PASSWORD", "WEIGHT": 2, "URL": PWD_VERIFY}
}
