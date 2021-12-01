package server

import (
	"encoding/hex"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/interfere/go-papyrus/v2/internal/papyrus"
	"github.com/pjebs/jsonerror"
	"go.uber.org/zap"
	"io"
	"net/http"
)

// Server server struct and its dependencies
type Server struct {
	lg      *zap.Logger
	service *papyrus.AuthService
}

// NewServer Creates the server with passed dependencies
func NewServer(logger *zap.Logger) *Server {
	return &Server{
		lg:      logger,
		service: papyrus.NewAuthService(),
	}
}

// RoutesHandler sets up the routes and handles them
func (s *Server) RoutesHandler() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(cors.AllowAll().Handler, NoStoreCacheControlMiddleware())

	r.NotFound(routeNotFoundHandler())
	r.MethodNotAllowed(methodNotAllowedHandler())

	r.Route("/v1", func(r chi.Router) {
		r.With(PapyrusAuthMiddleware(s.service, s.lg)).Post("/echo", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			if _, err := io.Copy(writer, request.Body); err != nil {
				s.lg.Fatal("Failed to read request body")
				http.Error(writer, "can't read body", http.StatusBadRequest)
				return
			}
		})

		r.Post("/auth/salt", func(w http.ResponseWriter, r *http.Request) {
			rCtx := r.Context()
			requestId := rCtx.Value(middleware.RequestIDKey).(string)
			logger := s.lg.With(zap.String("request_id", requestId))

			var saltReq papyrus.SaltReq
			if err := json.NewDecoder(r.Body).Decode(&saltReq); err != nil {
				logger.Error("Failed to parse salt request", zap.Error(err))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			if saltReq.Login == "" {
				logger.Error("Empty login string")
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			user, err := s.service.RegisterNewUser(saltReq.Login)
			if err != nil {
				logger.Error("Failed to register a new user", zap.Error(err))
				writeErrorResponse(w, http.StatusInternalServerError)
				return
			}

			saltRes := papyrus.SaltRes{
				Salt: hex.EncodeToString(user.Salt),
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)

			if err := json.NewEncoder(w).Encode(saltRes); err != nil {
				logger.Error("Failed to encode salt response", zap.Error(err))
			}
		})

		r.Put("/auth/verifier", func(w http.ResponseWriter, r *http.Request) {
			rCtx := r.Context()
			requestId := rCtx.Value(middleware.RequestIDKey).(string)
			logger := s.lg.With(zap.String("request_id", requestId))

			var verifierReq papyrus.VerifierReq
			if err := json.NewDecoder(r.Body).Decode(&verifierReq); err != nil {
				logger.Error("Failed to parse verifier request", zap.Error(err))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			if verifierReq.Login == "" {
				logger.Error("Empty login string")
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			v, err := hex.DecodeString(verifierReq.Verifier)
			if err != nil {
				logger.Error("Failed to parse verifier request", zap.Error(err))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			if err := s.service.SaveVerifier(verifierReq.Login, v); err != nil {
				logger.Error("Failed to save verifier", zap.String("login", verifierReq.Login), zap.Error(err))
				writeErrorResponse(w, http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
		})

		r.Post("/auth/handshake", func(w http.ResponseWriter, r *http.Request) {
			rCtx := r.Context()
			requestId := rCtx.Value(middleware.RequestIDKey).(string)
			logger := s.lg.With(zap.String("request_id", requestId))

			var handshakeReq papyrus.HandshakeReq
			if err := json.NewDecoder(r.Body).Decode(&handshakeReq); err != nil {
				logger.Error("Failed to parse handshake request", zap.Error(err))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			if handshakeReq.Login == "" || handshakeReq.ClientEphemeral == "" {
				logger.Error("Empty field in request")
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			clientEphemeral, err := hex.DecodeString(handshakeReq.ClientEphemeral)
			if err != nil {
				logger.Error("Failed to decode hex", zap.String("client_ephemeral", handshakeReq.ClientEphemeral))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			handshakeInfo, err := s.service.StartHandshake(handshakeReq.Login, clientEphemeral)
			if err != nil {
				logger.Error("Failed to start handshake", zap.Error(err))
				writeErrorResponse(w, http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)

			if err := json.NewEncoder(w).Encode(handshakeInfo.ConvertToResponse()); err != nil {
				logger.Error("Failed to encode handshake response", zap.Error(err))
			}
		})

		r.Post("/auth/session", func(w http.ResponseWriter, r *http.Request) {
			rCtx := r.Context()
			requestId := rCtx.Value(middleware.RequestIDKey).(string)
			logger := s.lg.With(zap.String("request_id", requestId))

			var sessionReq papyrus.SessionReq
			if err := json.NewDecoder(r.Body).Decode(&sessionReq); err != nil {
				logger.Error("Failed to parse session request", zap.Error(err))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			if sessionReq.Token == "" || sessionReq.ClientSessionKeyProof == "" {
				logger.Error("Empty field in request")
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			clientSessionKeyProof, err := hex.DecodeString(sessionReq.ClientSessionKeyProof)
			if err != nil {
				logger.Error("Failed to decode hex", zap.String("client_proof", sessionReq.ClientSessionKeyProof))
				writeErrorResponse(w, http.StatusBadRequest)
				return
			}

			serverSessionKeyProof, err := s.service.FinishHandshake(sessionReq.Token, clientSessionKeyProof)
			if err != nil {
				logger.Error("Failed to verify client proof", zap.String("client_proof", sessionReq.ClientSessionKeyProof))
				writeErrorResponse(w, http.StatusInternalServerError)
				return
			}

			sessionRes := papyrus.SessionRes{ServerSessionKeyProof: hex.EncodeToString(serverSessionKeyProof)}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)

			if err := json.NewEncoder(w).Encode(sessionRes); err != nil {
				logger.Error("Failed to encode session response", zap.Error(err))
			}
		})
	})

	return r
}

func routeNotFoundHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := jsonerror.New(http.StatusNotFound, "Route not found", "")
		writeErrorResponse(w, http.StatusNotFound, err)
	}
}

func methodNotAllowedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := jsonerror.New(http.StatusMethodNotAllowed, "Method not allowed", "")
		writeErrorResponse(w, http.StatusMethodNotAllowed, err)
	}
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, errResponse ...jsonerror.JE) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	if len(errResponse) < 1 {
		return
	}

	err := errResponse[0]
	if err := json.NewEncoder(w).Encode(err.Render()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
