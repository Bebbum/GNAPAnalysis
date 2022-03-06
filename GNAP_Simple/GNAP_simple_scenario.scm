(herald "Grant Negotiation and Authorization Protocol"
	(limit 200)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

;*******************************************;
; 			SCENARIO DESCRIPTION			;
;*******************************************;
; 1. Secure TLS connection is assumed for all cases using uni-directional long-term keys. (ex. (ltk c as) (ltk as c))
; 2. The client requests a token from the AS using its identity and what access it requires.
; 3. The AS evaluates the request and generates a token, signs it with its public key and encrypts it all with the public key of
; the RS since the contents of the token are opaque to the client instance.
; 4. The client then uses this token to access the RS.
; 5. The RS processes the request and sends an acknowledgement that the message was recieved.
; 6. In the skeleton definition we ensure the attacker does not have access to any of the private keys as well as keys related
; to the secure TLS connection.

(defprotocol single_token_simple basic
	(defrole client
		(vars (c as rs name) (access acess_token value access_type response data) )
		(trace
			; (Section 12.16 p.123) Since TLS protects the entire HTTP message in transit, verification of the TLS client 
			; certificate presented with the message provides a sufficient binding between the two.
			
			; (Section 12.5 p.114) With asymmetric keys, the client needs only to send its public key to  the AS to allow for 
			; verification that the client holds the associated private key, regardless of whether that key was pre-registered
			; or not with the AS.
			(send (enc c access (ltk c as)))
			(recv (enc (enc (cat acess_token value access_type (pubk as)) (pubk rs)) (ltk as c)))
			(send (enc (enc (cat acess_token value access_type (pubk as)) (pubk rs)) (ltk c rs)))
			(recv (enc response (ltk rs c)))
		)
	)
	(defrole authorization_server
		(vars (c as rs name) (access acess_token value access_type data))
		(trace
			; For access_token REQUIRED value and RECOMMENDED access with REQUIRED type are included
			
			; (Section 12.6 p.115-116) The content of access tokens need to be such that only the generating AS would be able to 
			; create them, and the contents cannot be manipulated by an attacker to gain different or additional access rights. 
			; One method for accomplishing this is to use a cryptographically random value for the access token, generated by the 
			; AS using a secure randomization function with sufficiently high entropy. Another method for accomplishing this 
			; is to use a structured token that is cryptographically signed. In this case, the payload of the access token declares
			; to the RS what the token is good for, but the signature applied by the AS during token generation covers this payload.
			
			; (Section 12.8 p.117) Key proofing mechanisms used with access tokens need to use replay protection mechanisms covered
			; under the signature such as a per-message nonce, a reasonably short time validity window, or other uniqueness 
			; constraints.
			
			; The access associated with the access token is described using objects that each contain multiple dimensions of access.
			; Each object contains a REQUIRED type property that determines the type of API that the token is used for.
			
			; (RS RFC Section 2 p.3) The core GNAP protocol makes no assumptions or demands on the format or contents of the access
			; token, and in fact the token format and contents are opaque to the client instance.
			(recv (enc c access (ltk c as)))
			(send (enc (enc (cat acess_token value access_type (pubk as)) (pubk rs)) (ltk as c)))
		)
	)
	(defrole resource_server
		(vars (c as rs name) (acess_token value access_type response data))
		(trace
			(recv (enc (enc (cat acess_token value access_type (pubk as)) (pubk rs)) (ltk c rs)))
			(send (enc response (ltk rs c)))
		)
	)
)

(defskeleton single_token_simple
  (vars (c as rs name))
  (defstrand client 4 (c c) (as as) (rs rs))
  (non-orig (privk c) (privk as) (privk rs) (ltk c as) (ltk as c) (ltk c rs) (ltk rs c))
)