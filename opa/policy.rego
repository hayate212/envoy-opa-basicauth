package envoy.authz

import future.keywords.if

default allow := {
  "allowed": false,
  "body": "Unauthorized Request",
  "http_status": 401,
  "headers": {  
    "WWW-Authenticate": "Basic"
  }
}

allow if {
  isAuthenticate
}

isAuthenticate if {
  token == "dXNlcjpwYXNzd29yZA=="
}

token := t if {
  v := input.attributes.request.http.headers.authorization
  startswith(v, "Basic ")
	t := substring(v, count("Basic "), -1)
}
