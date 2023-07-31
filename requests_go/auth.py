import warnings
from base64 import b64encode

basestring = (str, bytes)


def to_native_string(string, encoding="ascii"):
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def _basic_auth_str(username, password):
    """Returns a Basic Auth string."""

    # "I want us to put a big-ol' comment on top of it that
    # says that this behaviour is dumb but we need to preserve
    # it because people are relying on it."
    #    - Lukasa
    #
    # These are here solely to maintain backwards compatibility
    # for things like ints. This will be removed in 3.0.0.
    if not isinstance(username, basestring):
        warnings.warn(
            "Non-string usernames will no longer be supported in Requests "
            "3.0.0. Please convert the object you've passed in ({!r}) to "
            "a string or bytes object in the near future to avoid "
            "problems.".format(username),
            category=DeprecationWarning,
        )
        username = str(username)

    if not isinstance(password, basestring):
        warnings.warn(
            "Non-string passwords will no longer be supported in Requests "
            "3.0.0. Please convert the object you've passed in ({!r}) to "
            "a string or bytes object in the near future to avoid "
            "problems.".format(type(password)),
            category=DeprecationWarning,
        )
        password = str(password)
    # -- End Removal --

    if isinstance(username, str):
        username = username.encode("latin1")

    if isinstance(password, str):
        password = password.encode("latin1")

    authstr = "Basic " + to_native_string(
        b64encode(b":".join((username, password))).strip()
    )

    return authstr
