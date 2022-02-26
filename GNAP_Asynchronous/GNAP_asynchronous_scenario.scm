(herald "Asynchronous Grant Negotiation and Authorization Protocol"
	(limit 5000)
	(comment "This protocol allows a piece of software, the client instance, to asynchronously request delegated authorization to resource servers and to request direct information"))


(defprotocol gnap_asynchronous basic 
  (defrole client
    (vars (c as rs name) (access access_token api continuation_uri continuation_token data))
    (trace
	(send (enc c access (ltk c as))) ; client requests access at the AS encrypted with its shared symmetric key		
        (recv (enc continuation_uri continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (send (enc access continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (recv (enc continuation_uri continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (send (enc access continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (recv (enc access_token (ltk c as))) ; AS responds with a single access token bound to the client's shared symmetric key
        (send (enc access_token (ltk c as))) ; The client uses the access token to call the RS 
	(recv (enc api (ltk c as))) ; The RS determines if the token is sufficient for the request by examining the token.
    )
  )
  (defrole authorization_server
    (vars (c as ro name) (access access_token continuation_uri continuation_token data))
    (trace
	(recv (enc c access (ltk c as))) ; AS processes request and determines what is needed to fulfill the request
        (send (enc continuation_uri continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (recv (enc access continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (send (enc continuation_uri continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (recv (enc access continuation_token (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
        (send (enc access_token (ltk c as))) ; AS responds with a single access token bound to the client's shared symmetric key
    )
  ) 
  (defrole resource_server
    (vars (as rs c name) (access_token api data))
    (trace
	(recv (enc access_token (ltk c as))) ; The RS determines if the token is sufficient for the request by examining the token.
	(send (enc api (ltk c as))) ; The RS returns an appropriate response for the API
    )
  )
)

(defskeleton gnap_asynchronous
  (vars (c as rs name) (continuation_uri continuation_token data))
  (defstrand client 8 (c c) (as as))
  (non-orig (ltk c as))
;  (uniq-orig continuation_uri continuation_token)
)
