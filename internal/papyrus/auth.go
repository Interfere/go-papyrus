package papyrus

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"github.com/google/go-cmp/cmp"
	"time"
)

type UserInfo struct {
	login    string
	verifier []byte
	Salt     []byte
}

type HandshakeInfo struct {
	user            UserInfo
	token           string
	randomParameter []byte
	clientEphemeral []byte
	serverEphemeral []byte
}

func (h *HandshakeInfo) ConvertToResponse() HandshakeRes {
	return HandshakeRes{
		Token:           h.token,
		Salt:            hex.EncodeToString(h.user.Salt),
		ServerEphemeral: hex.EncodeToString(h.serverEphemeral),
	}
}

type SessionInfo struct {
	user  UserInfo
	token string
	key   []byte
}

type AuthService struct {
	suit      *Suite
	users     map[string]UserInfo
	handshake map[string]HandshakeInfo
	sessions  map[string]SessionInfo
}

func NewAuthService() *AuthService {
	return &AuthService{
		suit:      NewSuite(time.Now().UnixNano()),
		users:     make(map[string]UserInfo, 100),
		handshake: make(map[string]HandshakeInfo, 32),
		sessions:  make(map[string]SessionInfo, 100),
	}
}

func (s *AuthService) RegisterNewUser(login string) (*UserInfo, error) {
	salt := make([]byte, 32)
	if err := s.suit.GenRandVal(salt); err != nil {
		return nil, err
	}

	info, found := s.users[login]
	if !found {
		info = UserInfo{
			login:    login,
			verifier: nil,
			Salt:     salt,
		}
	} else {
		if info.verifier != nil {
			return nil, errors.New("User already exists")
		}
		info.Salt = salt
	}

	s.users[login] = info
	return &info, nil
}

func (s *AuthService) SaveVerifier(login string, verifier []byte) error {
	user, found := s.users[login]
	if !found {
		return errors.New("User does not exist")
	}

	s.users[login] = UserInfo{
		login:    user.login,
		verifier: verifier,
		Salt:     user.Salt,
	}

	return nil
}

func (s *AuthService) StartHandshake(login string, clientEphemeral []byte) (*HandshakeInfo, error) {
	user, found := s.users[login]
	if !found || user.verifier == nil {
		return nil, errors.New("User does not exist")
	}

	token := make([]byte, 32)
	if err := s.suit.GenRandVal(token); err != nil {
		return nil, errors.New("Failed to generate a token")
	}

	handshake := HandshakeInfo{
		user:            user,
		token:           hex.EncodeToString(token),
		randomParameter: make([]byte, KeyLen),
		clientEphemeral: clientEphemeral,
		serverEphemeral: make([]byte, KeyLen),
	}

	if err := s.suit.GenRandVal(handshake.randomParameter); err != nil {
		return nil, err
	}

	s.suit.GenServerEphemeralKey(handshake.serverEphemeral, handshake.randomParameter, user.verifier)
	s.handshake[handshake.token] = handshake
	return &handshake, nil
}

func (s *AuthService) FinishHandshake(token string, clientProof []byte) ([]byte, error) {
	handshake, found := s.handshake[token]
	if !found {
		return nil, errors.New("No handshake in progress")
	}

	sessionKey := s.suit.GenServerSessionKey(
		handshake.randomParameter,
		handshake.clientEphemeral,
		handshake.serverEphemeral,
		handshake.user.verifier)

	refProof := s.suit.GenClientSessionKeyProof([]byte(handshake.user.login), handshake.user.Salt, handshake.clientEphemeral, handshake.serverEphemeral, sessionKey)
	if !cmp.Equal(refProof, clientProof) {
		return nil, errors.New("Invalid session key proof")
	}

	delete(s.handshake, token)

	session := SessionInfo{
		user:  handshake.user,
		token: handshake.token,
		key:   sessionKey,
	}
	serverProof := s.suit.GenServerSessionKeyProof(handshake.clientEphemeral, clientProof, sessionKey)
	s.sessions[token] = session
	return serverProof, nil
}

func (s *AuthService) VerifySignature(token string, sig []byte, body []byte) bool {
	session, found := s.sessions[token]
	if !found {
		return false
	}

	hasher := hmac.New(sha512.New, session.key)
	if _, err := hasher.Write(body); err != nil {
		return false
	}

	return cmp.Equal(sig, hasher.Sum(nil))
}
