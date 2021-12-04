# Papyrus Auth Protocol

Papyrus is a SRP-based protocol covering authentication and authroization of HTTP requests.

## Registration Example

* *Create salt*
	```
	curl -X POST -H 'Content-Type: application/json' -d '{"l":"1234"}' http://localhost:8080/v1/auth/salt
	```

* *Save verifier*
	```
	curl -i -X PUT -H 'Content-Type: application/json' \
	-d '{"l":"1234","v":"87c1970db23207e8708ba81cd012bd443f5e2c62d93ecfe398c8c0ee5a2314555d2afd7820e96324b50f8f761103e9f6ba519d754a85e5cb673fa902a7b0724749cef36a75ba77d8d0ade7cc3602099ba7f9f8fb3f525f93107ba0855162f9613d52acfc059027b5ec4c31cf1c2756cce0f2d6259168a57a63ead558aece25a5e79cd18c9c1220c16f54789b152bed749bd92328e29cdcb3fc71c6bc553208776b9fed913a7ce03a6e47d698db9f47be223664e8383e02de393209c566b5f3d1160e1397c681412f6e63546b985b58d1da1670f54144972cb96e5172480d003207e3600b1e5cad88a2f27fe5747338a54d15318b0be9c303ad2a96e42ec71311"}' \
	http://localhost:8080/v1/auth/verifier
	```

## Login example

* *Begin handshake procedure*
	```
	curl -i -X POST -H 'Content-Type: application/json' \
	-d '{"l":"1234","A":"3a71624993b7b6617411e7a66e6dd3abbec5f207d6912ee8402897846b0e4d0469d65ffac83c86d09b40de2c7ac212385817449642a9c66bfb29bfbb2a44ecda4a323db60c729becfb822112686cb057f9effaaf91fc8012dc6d754d841a9eff4be317ec188649e7ab2e3e78de864b4a5315aef4d13c1de245e3dc8439a7ae95aed14b9b55b1fd4d6234b9df4d1e8f2a4ea3dc4275ecbb0efc2d3f17be2d99197c28f42f46f690a822c9f7634a93b1f82bf5bc72657646b8693f387bf2b6dc98bad0fe498426631864c58d92db1b13391866b580553f883ce3711f3948ce91ec9c6236883b826a2f7221ba672aae36588fb69a597c6e8b6a4508400ef1e268c5"}' \
	http://localhost:8080/v1/auth/handshake
	```	

* *Start session*
	```
	curl -i -X POST -H 'Content-Type: application/json' \
	-d '{"token":"dd16e07867f71009a602ab6450f0c6832201d0aea34e11b1ab904af0ffb8c513","M":"1c471ae0294830f90406ca09b41c1efac99e005b4fa23e8aad47e4f53d21f1865da9b02750e7aacee40b6a18ce2d564591647cf0f5ff2445782153c79e30f48f"}' \
	http://localhost:8080/v1/auth/session
	```	

## Authorized request example
	
	curl -i -X POST -H 'Content-Type: application/json' \
	-H "Authorization: Bearer dd16e07867f71009a602ab6450f0c6832201d0aea34e11b1ab904af0ffb8c513" \
	-H "X-Signature: e984f4c5eeeee7b7e0a28e14fea4e2f91dcbf4d3bfdc7e81a0e10c282b017aa977ae87dfefca484c80fa059c832be1eebb0cd0fe1947bd093ea35beb4b3e21ff" \
	-d '{"msg":"Hello"}' \
	http://localhost:8080/v1/echo
	

[papyrus.py](papyrus.py) is a script that may be used to generate request parameters and session key.