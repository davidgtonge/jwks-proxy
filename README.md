# jwks-proxy
Simple proxy server that proxies jwks endpoints and adds CORS headers

The use case for this is a utility that verifies JSON Web Tokens in the browser and needs access to the public keys of the issuer of the token from the issuer's `jwks_uri`.

This should only be used for debugging purposes.
