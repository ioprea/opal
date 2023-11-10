package app.rbac
import future.keywords.in

default allow := false

bearer_token := t {
	v := input.jwt
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}

claims := payload {
	[_, payload, _] := io.jwt.decode(bearer_token)
}

allow {
	some role in claims.session.identity.traits.roles
	role == "admin"
}

allow {
	some role in claims.session.identity.traits.roles
	role == "meeting_planner"
}
