(herald "Asynchronous Grant Negotiation and Authorization Protocol"
	(limit 100000)
	(comment "This protocol allows a piece of software, the client instance, to asynchronously request delegated authorization to resource servers and to request direct information"))


(defprotocol gnap_asynchronous basic 
  (defrole client
  	(vars (as c rs name) (access access_token access_type continuation_token continuation_uri response value data) (n1 n2 n3 n4 text))
  	(trace
		(send (enc c n1 (pubk as)))
		(recv (enc as n1 n2 (pubk c)))
		(send (enc n2 (pubk as)))
		(send (enc c access (hash n1 n2)))
		(recv (enc (enc (enc (cat continuation_token continuation_uri) (privk as)) (pubk rs)) (hash n1 n2)))
		(send (enc (enc (enc (cat continuation_token access) (privk as)) (pubk rs)) (hash n1 n2)))
		(recv (enc (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
		(send (enc c n3 (pubk rs)))
		(recv (enc as n3 n4 (pubk c)))
		(send (enc n4 (pubk rs)))
		(send (enc (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
		(recv (enc response (hash n3 n4)))
    	)
  )
  (defrole authorization_server
  	(vars (as c rs name) (access access_token access_type continuation_token continuation_uri value data) (n1 n2 text) (k akey))
  	(trace
		(recv (enc c n1 (pubk as)))
		(send (enc as n1 n2 (pubk c)))
		(recv (enc n2 (pubk as)))
		(recv (enc c access (hash n1 n2)))
		(send (enc (enc (enc (cat continuation_token continuation_uri) (privk as)) (pubk rs)) (hash n1 n2)))
		(recv (enc (enc (enc (cat continuation_token access) (privk as)) (pubk rs)) (hash n1 n2)))
		(send (enc (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
    	)
  ) 

  (defrole resource_server
  	(vars (as c rs name) (access access_token access_type response value data) (n3 n4 text))
  	(trace
		(recv (enc c n3 (pubk rs)))
		(send (enc rs n3 n4 (pubk c)))
		(recv (enc n4 (pubk rs)))
		(recv (enc (enc (enc (cat access_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
		(send (enc response (hash n3 n4)))
  	)
  )
)

(defskeleton gnap_asynchronous
  (vars (c as rs name) (n1 n3 text))
  (defstrand client 12 (c c) (as as) (rs rs) (n1 n1) (n3 n3))
  (uniq-orig n1 n3)
  (non-orig (privk c) (privk as) (privk rs))
  (neq (c as) (c rs) (as rs)) 
)
