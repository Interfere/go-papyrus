package papyrus

type SaltReq struct {
	Login string `json:"l"`
}

type SaltRes struct {
	Salt string `json:"s"`
}

type VerifierReq struct {
	Login    string `json:"l"`
	Verifier string `json:"v"`
}

type HandshakeReq struct {
	Login           string `json:"l"`
	ClientEphemeral string `json:"A"`
}

type HandshakeRes struct {
	Token           string `json:"token"`
	Salt            string `json:"s"`
	ServerEphemeral string `json:"B"`
}

type SessionReq struct {
	Token                 string `json:"token"`
	ClientSessionKeyProof string `json:"M"`
}

type SessionRes struct {
	ServerSessionKeyProof string `json:"M"`
}
