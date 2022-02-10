(herald "Grant Negotiation and Authorization Protocol"
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

(defprotocol gnap_simple basic
	(defrole client
		(vars (a b name) (m1 m2 m3 text))
		(trace
			(send m1) ; client requests access at the AS
			(recv m2) ; does this message contain a continuation access token?
			(send m3) ; continues grant at the AS ;; access to the AS continuation API?
			(recv acess_token_1)
			(send acess_token_1)
			; The client instance calls the RS (Section 7.2) using the access token until the RS or client instance determine that the token is no longer valid.
			(send fetch_token) ; When the token no longer works, the client instance fetches an updated access token (Section 6.1) based on the rights granted in line 11.
			(recv acess_token_2)
			(send acess_token_2) ; The client instance uses the new access token (Section 7.2) to call the RS.
			(send dispose_token_2) ; The client instance disposes of the token (Section 6.2) once the client instance has completed its access of the RS and no longer needs the token.
		)
	)
	(defrole authorization_server
		(vars (a b name) (m1 m2 m3 text))
		(trace
			(recv m1) ; AS processes request and determines what is needed to fulfill the request
			(send m2) ; AS sends its response to client instance
			(recv m3)
			(send acess_token_1) ; If the AS determines that access can be granted, it returns a response to the client instance (Section 3) including an access token (Section 3.2) for calling the RS and any directly returned information (Section 3.4) about the RO
			(recv fetch_token)
			(send acess_token_2) ; The AS issues a new access token (Section 3.2) to the client instance.
			(recv dispose_token_2)
		)
	)
	(defrole resource_server
		(vars (a b name) (r text))
		(trace
			(recv acess_token_1) ; The RS determines if the token is sufficient for the request by examining the token.
			(recv acess_token_2) ; The RS determines if the new token is sufficient for the request.
		)
	)
)

(defskeleton gnap_simple
  (vars ())
  (defstrand client 9 (a a) (b b) (c c))
  (non-orig ())
  (uniq-orig )
  (comment "")
)

(defskeleton gnap_simple
  (vars ())
  (defstrand authorization_server 7 (a a) (b b) (c c))
  (non-orig ())
  (uniq-orig )
  (comment "")
)

(defskeleton gnap_simple
  (vars ())
  (defstrand resource_server 2 (a a) (b b) (c c))
  (non-orig ())
  (uniq-orig )
  (comment "")
)
