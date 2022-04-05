(herald "Grant Negotiation and Authorization Protocol"
	(limit 10000)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))
	
	; In RFC 5246 TLS 1.2 Appendix-F.1.4, states:
	; When a connection is established by resuming a session, new ClientHello.random and ServerHello.random values are hashed with the session's Master Secret. 
	; Provided that the Master Secret has not been compromised and that the secure hash operations used to produce the encryption keys and MAC keys are secure, 
	; the connection should be secure and effectively independent from previous connections.

(defprotocol token_refresh basic
	(defrole client
		(vars (c as rs name) (access management_uri management_uri_new value response data) (n1 n2 n3 n4 text) (token token_new mesg))
		(trace
			; NSL TLS connection with AS
			(send (enc c n1 (pubk as)))
			(recv (enc as n1 n2 (pubk c)))
			(send (enc n2 (pubk as)))
			; Begin transaction with AS
			(send (enc c access (hash n1 n2)))
			(recv (enc management_uri token (hash n1 n2)))
			; NSL TLS connection with RS
			(send (enc c n3 (pubk rs)))
			(recv (enc rs n3 n4 (pubk c)))
			(send (enc n4 (pubk rs)))
			; Begin transaction with RS
			(send (enc token (hash n3 n4)))
			(recv (enc response (hash n3 n4)))
			(send (enc token (hash n3 n4)))
			(recv (enc response (hash n3 n4)))
			; Begin refresh of token with AS
			(send (enc token (hash n1 n2)))
			(recv (enc management_uri_new token_new (hash n1 n2)))
			; Begin transaction with RS after token refresh at AS
			(send (enc token_new (hash n3 n4)))
			(recv (enc response (hash n3 n4)))
		)
		  (uniq-orig n1 n3)
	)
	(defrole authorization_server
		(vars (c as rs name) (access access_token access_token_new access_type management_uri management_uri_new value data) (n1 n2 text))
		(trace
			; NSL TLS connection with Client
			(recv (enc c n1 (pubk as)))
			(send (enc as n1 n2 (pubk c))) 
			(recv (enc n2 (pubk as)))
			; Begin transaction with Client
			(recv (enc c access (hash n1 n2)))
			(send (enc management_uri (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
			; Begin transaction with Client for token refresh
			(recv (enc (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
			(send (enc management_uri_new (enc (enc (cat access_token_new value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
		)
		  (uniq-orig n2)
	)
	(defrole resource_server
		(vars (c as rs name) (access_token access_token_new value access_type response data) (n3 n4 text))
		(trace
			; NSL TLS connection with Client
			(recv (enc c n3 (pubk rs)))
			(send (enc rs n3 n4 (pubk c)))
			(recv (enc n4 (pubk rs)))
			; Begin transcation with Client
			(recv (enc (enc (enc  (cat access_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response (hash n3 n4)))
			(recv (enc (enc (enc  (cat access_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response (hash n3 n4)))
			; Begin transaction with Client after token refresh at AS
			(recv (enc (enc (enc (cat access_token_new value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response (hash n3 n4)))
		)
		(uniq-orig n4)
	)
)

(defskeleton token_refresh 
  (vars (c as rs name) (management_uri management_uri_new response data) (token token_new mesg))
  (defstrand client 16 (c c) (as as) (rs rs) (management_uri management_uri) (management_uri_new management_uri_new) (token token) (token_new token_new))
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs) (management_uri management_uri_new) (token token_new)) 
)

(defskeleton token_refresh 
  (vars (c as rs name) (management_uri management_uri_new access_token access_token_new data))
  (defstrand authorization_server 7 (c c) (as as) (rs rs) (management_uri management_uri) (management_uri_new management_uri_new) (access_token access_token) (access_token_new access_token_new))
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs) (management_uri management_uri_new) (access_token access_token_new)) 
)

(defskeleton token_refresh 
  (vars (c as rs name) (access_token access_token_new data))
  (defstrand resource_server 9 (c c) (as as) (rs rs) (access_token access_token) (access_token_new access_token_new))
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs) (access_token access_token_new)) 
)
