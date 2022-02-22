(herald "Grant Negotiation and Authorization Protocol"
	(limit 5000)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

(defprotocol single_token_simple basic
	(defrole client
		(vars (c as name) (access acess_token data))
		(trace
			(send (enc c access (ltk c as))) ; client requests access at the AS encrypted with its shared symmetric key		
			(recv (enc acess_token (ltk c as))) ; receives access token from AS	
			(send (enc acess_token (ltk c as))) ; The client instance uses the access token to call the RS.
			(send (enc acess_token (ltk c as))) ; The client instance disposes of the token once the client instance has completed its access of the RS and no longer needs the token.
		)
	)
	(defrole authorization_server
		(vars (c as name) (access acess_token data))
		(trace
			(recv (enc c access (ltk c as))) ; AS processes request and determines what is needed to fulfill the request
			(send (enc acess_token (ltk c as))) ; AS responds with a single access token bound to the client's shared symmetric key
			(recv (enc acess_token (ltk c as))) ; Receives request to delete the access token
		)
	)
	(defrole resource_server
		(vars (c as name) (acess_token data))
		(trace
			(recv (enc acess_token (ltk c as))) ; The RS determines if the token is sufficient for the request by examining the token.
		)
	)
)

(defskeleton single_token_simple
  (vars (c as name))
  (defstrand client 4 (c c) (as as))
  (non-orig (ltk c as))
)
