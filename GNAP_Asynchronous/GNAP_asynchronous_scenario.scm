(herald "Asynchronous Grant Negotiation and Authorization Protocol"
	(limit 10000)
	(comment "This protocol allows a piece of software, the client instance, to asynchronously request delegated authorization to resource servers and to request direct information"))


(defprotocol gnap_asynchronous basic 
  (defrole client
    (vars (c as rs name) (access access_token api continuation_uri continuation_token response value data) (n1 n2 n3 text) (k akey))
    (trace
	(send (enc c access (pubk c) (ltk c as))) ; client requests access at the AS encrypted with its shared symmetric key		
	(recv (enc (enc n1 (cat continuation_token continuation_uri) (pubk c)) (ltk c as)))
        (send (enc n1 access continuation_token (pubk c) (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
	(recv (enc (enc n2 (enc (cat access_token value access) (invk k)) (pubk c)) (ltk c as))) ; receives and decrypts message using private key whic results in a usable access token
	(send (enc (enc n3 (enc (cat access_token value access) (invk k)) (pubk c)) (ltk c rs))) ; The client instance uses the access token to call the RS.
	(recv (enc (enc response (pubk c)) (ltk c rs)))
    )
  )
  (defrole authorization_server
    (vars (c as ro name) (access access_token continuation_uri continuation_token value data) (n1 n2 text) (k akey))
    (trace
	(recv (enc c access (pubk c) (ltk c as))) ; AS processes request and determines what is needed to fulfill the request
	(send (enc (enc n1 (cat continuation_token continuation_uri) (pubk c)) (ltk c as)))
        (recv (enc access continuation_token (pubk c) (ltk c as))) ; AS responds with the information the client instance will need to continue the request 
	(send (enc (enc n2 (enc (cat access_token value access) (invk k)) (pubk c)) (ltk c as))) ; AS signs token and binds it to client's public key
    )
  ) 

  (defrole resource_server
  	(vars (c rs name) (access_token value access response data) (n3 text) (k akey))
  	(trace
  		(recv (enc (enc n3 (enc (cat access_token value access) (invk k)) (pubk c)) (ltk c rs))) ; RS decrypts and validates the client's token
  		(send (enc (enc response (pubk c)) (ltk c rs)))
  	)
  )
)

(defskeleton gnap_asynchronous
  (vars (c as rs name) (continuation_uri continuation_token data) (k akey) (n3 text))
  (defstrand client 6 (c c) (as as) (rs rs) (n3 n3) (k k))
  (non-orig (ltk c as) (ltk c rs) k)
  (uniq-orig n3)
)
