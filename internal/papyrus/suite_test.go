package papyrus

import (
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	kPasswordHex           = "7f1c0546a2220e97dc63d61925025bebed76b6370f1f48fad2d4ff6dc083a94b5691c95dba077106ce52dce8f72efe9e5d591f7a8f793a22d28fee154db31146"
	kSaltHex               = "9156dc6f87d466102ab8792ccaff574fd90edc80aaba24b29780ee728bcf7ea5d195852311971f4a1334ed893c96e71fd81693e7c64c2fbb95faa07591318ebc"
	kVerifierHex           = "9fc22c3a13f2d020d1f336af1b4b8256e9a199119b6e10723ae5afca3d291bbe507fbb2d26eae149b83a4a2e8bae91c0a5e439401364057b41edd8d4d41bcf8490e0752654ec15d6826ff43348de95dc61367328b478d3460269f9e12489ac53d45b2fabe597fbfcf18cc40b731f2cd6dfaeaf3e997a3b22144e5bf7c514c5ab18059027e512b4b41ba7cdb9a56ade86010af57e56b394b64b9e0881de688350c0103215bbded191dc397c12aa6c2a4c899008cb84bbffee46f30f99a945e6661a0edf64b6d1b030398840269a98af92582a20d93c874b0147bca6be3767865bd6b96a55a05b16c87677bf8e796e008137db4e949ccd187626426d3f8bab98f3"
	kClientPrivateKeyHex   = "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac"
	kClientEphemeralKeyHex = "15d9d3b12cb1ea5503a216a59f018b28a68086ec92dffaeabb98e321e51300c37f995b74a78e1134069f414f23e79a761f3a5c16c2d3ef5ac4b2d06e482c1e89b80562729b2b90517eb540bccc6af992fde364187ee1c244f98a906f2608dda4b161ec85bf703e2407aa4df76f7bbd59ff89e47a969ed24280b8d2b2e3c971a39a78c02127e477042eba6d673a015eee0833f8e4773fb27bfb7615e51d7ee205836d507ba130c108851becac8504467cc2716fb5c30e46df88c74c98def71ce0a5f58ebed5964bf5c59236e151a1f79fda391acd256df22c6cc358bfd116acc390223a542697e2574a672a88624fb820fef1901ed12488bd253450b88abbf656"
	kServerPrivateKeyHex   = "cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca"
	kServerEphemeralKeyHex = "8bce584ccc33dccc59cf8afbc0857c1249470ac060c791eadff9fb937d7dc7188937b2bc9dd1c26139ab7206aa800e5184fd9530b38f7d91ed3d787218442d6d89953c0cc23ef45aae6b4ba89aa413fe5daa5509ac785dced7646a5082000fddc7234e8897745aeec6f35532268c4617fedcfcbbef5a44ccb8d52ccc0e3b0103f9a9d05dcdb3db29d69bbfab7fb6245a8d8e228eb2c6287f0127def6d2231c565d1f16b565e1d004dd710029d6b28f6c6d82887bc0c5856aca91c9bb7c46c8039b85f2109ad91d1e14103fadcdf5fd37ec9553b3d81667818cbd486edbdc3730e2920594d8d0f7bb4077412c288e7acb4fd203026f6578c51029f93f37f89a09"
	kSessionKeyHex         = "cb9956928b539384665b4fb5b26250789834a0a9388746203a692269bed98da875af923922d36d326f5eb9419d04d2f66363d6031957046c20ad6e5fe0e867da"
)

func TestSuite_GenVerifier(t *testing.T) {
	//: given
	password, err := hex.DecodeString(kPasswordHex)
	if err != nil {
		t.Fatalf("Failed to decode kPasswordHex %s", err.Error())
	}

	salt, err := hex.DecodeString(kSaltHex)
	if err != nil {
		t.Fatalf("Failed to decode kSaltHex %s", err.Error())
	}

	refVerifier, err := hex.DecodeString(kVerifierHex)
	if err != nil {
		t.Fatalf("Failed to decode kVerifierHex %s", err.Error())
	}

	//: when
	verifier := make([]byte, KeyLen)
	NewSuite(0).GenVerifier(verifier, password, salt)

	//: then
	if !cmp.Equal(refVerifier, verifier) {
		t.Errorf("Mismatch:\n%s\n%s", kVerifierHex, hex.EncodeToString(verifier))
	}
}

func TestSuite_GenClientEphemeralKey(t *testing.T) {
	//: given
	clientPrivateKey, err := hex.DecodeString(kClientPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kClientPrivateKeyHex %s", err.Error())
	}

	refClientEphemeralKey, err := hex.DecodeString(kClientEphemeralKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kClientEphemeralKeyHex %s", err.Error())
	}

	//: when
	clientEphemeralKey := make([]byte, KeyLen)
	NewSuite(0).GenClientEphemeralKey(clientEphemeralKey, clientPrivateKey)

	//: then
	if !cmp.Equal(refClientEphemeralKey, clientEphemeralKey) {
		t.Errorf("Mismatch:\n%s\n%s", kClientEphemeralKeyHex, hex.EncodeToString(clientEphemeralKey))
	}
}

func TestSuite_GenServerEphemeralKey(t *testing.T) {
	//: given
	serverPrivateKey, err := hex.DecodeString(kServerPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kServerPrivateKeyHex %s", err.Error())
	}

	refServerEphemeralKey, err := hex.DecodeString(kServerEphemeralKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kServerEphemeralKeyHex %s", err.Error())
	}

	verifier, err := hex.DecodeString(kVerifierHex)
	if err != nil {
		t.Fatalf("Failed to decode kVerifierHex %s", err.Error())
	}

	//: when
	serverEphemeralKey := make([]byte, KeyLen)
	NewSuite(0).GenServerEphemeralKey(serverEphemeralKey, serverPrivateKey, verifier)

	//: then
	if !cmp.Equal(refServerEphemeralKey, serverEphemeralKey) {
		t.Errorf("Mismatch:\n%s\n%s", kServerEphemeralKeyHex, hex.EncodeToString(serverEphemeralKey))
	}
}

func TestSuite_GenServerSessionKey(t *testing.T) {
	//: given
	serverPrivateKey, err := hex.DecodeString(kServerPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kServerPrivateKeyHex %s", err.Error())
	}

	serverEphemeralKey, err := hex.DecodeString(kServerEphemeralKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kServerEphemeralKeyHex %s", err.Error())
	}

	clientEphemeralKey, err := hex.DecodeString(kClientEphemeralKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kClientEphemeralKeyHex %s", err.Error())
	}

	verifier, err := hex.DecodeString(kVerifierHex)
	if err != nil {
		t.Fatalf("Failed to decode kVerifierHex %s", err.Error())
	}

	refSessionKey, err := hex.DecodeString(kSessionKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kSessionKeyHex %s", err.Error())
	}

	//: when
	sessionKey := NewSuite(0).GenServerSessionKey(serverPrivateKey, clientEphemeralKey, serverEphemeralKey, verifier)

	//: then
	if !cmp.Equal(refSessionKey, sessionKey) {
		t.Errorf("Mismatch:\n%s\n%s", kSessionKeyHex, hex.EncodeToString(sessionKey))
	}
}

func TestSuite_GenClientSessionKey(t *testing.T) {
	//: given
	clientPrivateKey, err := hex.DecodeString(kClientPrivateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kClientPrivateKeyHex %s", err.Error())
	}

	serverEphemeralKey, err := hex.DecodeString(kServerEphemeralKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kServerEphemeralKeyHex %s", err.Error())
	}

	clientEphemeralKey, err := hex.DecodeString(kClientEphemeralKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kClientEphemeralKeyHex %s", err.Error())
	}

	password, err := hex.DecodeString(kPasswordHex)
	if err != nil {
		t.Fatalf("Failed to decode kPasswordHex %s", err.Error())
	}

	salt, err := hex.DecodeString(kSaltHex)
	if err != nil {
		t.Fatalf("Failed to decode kSaltHex %s", err.Error())
	}

	refSessionKey, err := hex.DecodeString(kSessionKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode kSessionKeyHex %s", err.Error())
	}

	//: when
	sessionKey := NewSuite(0).GenClientSessionKey(clientPrivateKey, clientEphemeralKey, serverEphemeralKey, password, salt)

	//: then
	if !cmp.Equal(refSessionKey, sessionKey) {
		t.Errorf("Mismatch:\n%s\n%s", kSessionKeyHex, hex.EncodeToString(sessionKey))
	}
}
