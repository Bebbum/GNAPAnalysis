(herald "Grant Negotiation and Authorization Protocol"
	(limit 3000)
	(depth 1000)
	(bound 16)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

(defprotocol token_refresh basic
	(defrole client
		(vars (c as rs name) (access  management_uri management_uri_new response response_error response_new value data) (n1 n2 n3 n4 text) (token token_new mesg))
		(trace
			(send (enc c n1 (pubk as)))
			(recv (enc as n1 n2 (pubk c)))
			(send (enc n2 (pubk as)))
			(send (enc c access (hash n1 n2)))
			(recv (enc management_uri token (hash n1 n2)))
			(send (enc c n3 (pubk rs)))
			(recv (enc rs n3 n4 (pubk c)))
			(send (enc n4 (pubk rs)))
			(send (enc token (hash n3 n4)))
			(recv (enc response (hash n3 n4)))
			(send (enc token (hash n3 n4)))
			(recv (enc response_error (hash n3 n4)))
			(send (enc token (hash n1 n2)))
			(recv (enc management_uri_new token_new (hash n1 n2)))
			(send (enc token_new (hash n3 n4)))
			(recv (enc response_new (hash n3 n4)))
		)
		  (uniq-orig n1 n3)
	)
	(defrole authorization_server
		(vars (c as rs name) (access access_token access_token_new access_type management_uri management_uri_new value data) (n1 n2 text))
		(trace
			(recv (enc c n1 (pubk as)))
			(send (enc as n1 n2 (pubk c))) 
			(recv (enc n2 (pubk as))) 
			(recv (enc c access (hash n1 n2)))
			(send (enc management_uri (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
			(recv (enc (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
			(send (enc management_uri_new (enc (enc (cat access_token_new value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
		)
		  (uniq-orig n2)
	)
	(defrole resource_server
		(vars (c as rs name) (access_token access_token_new value access_type response response_error response_new data) (n3 n4 text))
		(trace
			(recv (enc c n3 (pubk rs)))
			(send (enc rs n3 n4 (pubk c)))
			(recv (enc n4 (pubk rs)))
			(recv (enc (enc (enc  (cat access_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response (hash n3 n4)))
			(recv (enc (enc (enc  (cat access_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response_error (hash n3 n4)))
			(recv (enc (enc (enc (cat access_token_new value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response_new (hash n3 n4)))
		)
		(uniq-orig n4)
	)
)

(defskeleton token_refresh 
  (vars (c as rs name) (n1 n3 text))
  (defstrand client 16 (c c) (as as) (rs rs) (n1 n1) (n3 n3))
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs)) 
)

(defskeleton token_refresh 
  (vars (c as rs name) (n2 text))
  (defstrand authorization_server 7 (c c) (as as) (rs rs) (n2 n2))
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs)) 
)

(defskeleton token_refresh 
  (vars (c as rs name) (n4 text))
  (defstrand resource_server 9 (c c) (as as) (rs rs) (n4 n4))
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs)) 
)
