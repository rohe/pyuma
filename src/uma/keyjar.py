from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import dump_jwks

__author__ = 'rolandh'


def init_keyjar(instance, keyspec, dump_filename="static/jwks.json"):
    try:
        instance.keyjar[""] = []
    except (AttributeError, TypeError):
        instance.keyjar = KeyJar()
        instance.jwks_uri = []
        instance.keyjar[""] = []

    kbl = []
    for typ, info in keyspec.items():
        typ = typ.upper()
        kb = KeyBundle(source="file://%s" % info["key"], fileformat="der",
                       keytype=typ)
        instance.keyjar.add_kb("", kb)
        kbl.append(kb)

    try:
        if dump_filename:
            dump_jwks(kbl, dump_filename)
            instance.jwks_uri.append("%s%s" % (instance.baseurl, dump_filename))
    except KeyError:
        pass

