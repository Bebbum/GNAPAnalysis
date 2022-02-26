(herald "Grant Negotiation and Authorization Protocol"
	(limit 50)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

(defprotocol single_token_simple basic
	(defrole client
		(vars (c as rs name) (access acess_token value rights response data) (n1 n2 text) (k akey))
		(trace
			; This assumes communcation over encrypted TLS connection (ltk c as)
			; (Section 12.5 p.114) With asymmetric keys, the client needs only to send its public key to  the AS to allow for 
			; verification that the client holds the associated private key, regardless of whether that key was pre-registered
			; or not with the AS.
			(send (enc c access (pubk c) (ltk c as))) ; client requests access at the AS by identifying itself and proving possession of a cryptogrphic key
			(recv (enc n1 (enc (cat acess_token value rights) k) (cat (pubk c) (ltk c as)))) ; receives and decrypts message using private key whic results in a usable access token
			(send (enc n2 (enc (cat acess_token value rights) k) (cat (pubk c) (ltk c rs)))) ; The client instance uses the access token to call the RS.
			(recv (enc response (cat (pubk c) (ltk c rs))))
		)
	)
	(defrole authorization_server
		(vars (c as name) (access acess_token value rights data) (n1 text) (k akey))
		(trace
			(recv (enc c access (pubk c) (ltk c as))) ; AS validates the client's request
			; For access_token REQUIRED value and RECOMMENDED rights are included
			; (Section 12.8 p.117) Key proofing mechanisms used with access tokens need to use replay protection mechanisms covered
			; under the signature such as a per-message nonce, a reasonably short time validity window, or other uniqueness 
			; constraints.
			(send (enc n1 (enc (cat acess_token value rights) k) (cat (pubk c) (ltk c as)))) ; AS signs token and binds it to client's public key
		)
	)
	(defrole resource_server
		(vars (c rs name) (acess_token value rights response data) (n2 text) (k akey))
		(trace
			(recv (enc n2 (enc (cat acess_token value rights) k) (cat (pubk c) (ltk c rs)))) ; RS decrypts and validates the client's token
			(send (enc response (cat (pubk c) (ltk c rs))))
		)
	)
)

(defskeleton single_token_simple
  (vars (c as rs name) (n2 text) (k akey))
  (defstrand client 4 (c c) (as as) (rs rs) (n2 n2) (k k))
  (non-orig (ltk c as) (ltk c rs) k)
  (uniq-orig n2)
)
