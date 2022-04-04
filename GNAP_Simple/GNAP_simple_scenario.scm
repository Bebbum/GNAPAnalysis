(herald "Grant Negotiation and Authorization Protocol"
	(limit 3000)
	(try-old-strands)
	(reverse-nodes)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

;*******************************************;
; 			SCENARIO DESCRIPTION			;
;*******************************************;
; 1. Secure TLS connection is created by utlizing Needham-Schroeder-Lowe
; 2. The client requests a token from the AS using its identity and what access it requires.
; 3. The AS evaluates the request and generates a token, signs it with its public key and encrypts it all with the public key of
; the RS since the contents of the token are opaque to the client instance.
; 4. The client then uses this token to access the RS.
; 5. The RS processes the request and sends an acknowledgement that the message was recieved.
; 6. In the skeleton definition we ensure the attacker does not have access to any of the private keys and that each defined role
; is unique/non-interchangeable

(defprotocol single_token_simple basic
	(defrole client
		(vars (c as rs name) (access response data) (n1 n2 n3 n4 text) (token mesg))
		(trace
			(send (enc c n1 (pubk as)))
			(recv (enc as n1 n2 (pubk c)))
			(send (enc n2 (pubk as)))
			(send (enc c access (hash n1 n2)))
			(recv (enc token (hash n1 n2)))
			(send (enc c n3 (pubk rs)))
			(recv (enc rs n3 n4 (pubk c)))
			(send (enc n4 (pubk rs)))
			(send (enc token (hash n3 n4)))
			(recv (enc response (hash n3 n4)))
		)
		(uniq-orig n1 n3)
	)
	(defrole authorization_server
		(vars (c as rs name) (access acess_token value access_type data) (n1 n2 text))
		(trace
			(recv (enc c n1 (pubk as)))
			(send (enc as n1 n2 (pubk c)))
			(recv (enc n2 (pubk as)))
			(recv (enc c access (hash n1 n2)))
			(send (enc (enc (enc  (cat acess_token value access_type) (privk as)) (pubk rs)) (hash n1 n2)))
		)
		(uniq-orig n2)
	)
	(defrole resource_server
		(vars (c as rs name) (acess_token value access_type response data) (n3 n4 text))
		(trace
			(recv (enc c n3 (pubk rs)))
			(send (enc rs n3 n4 (pubk c)))
			(recv (enc n4 (pubk rs)))
			(recv (enc (enc (enc  (cat acess_token value access_type) (privk as)) (pubk rs)) (hash n3 n4)))
			(send (enc response (hash n3 n4)))
		)
		(uniq-orig n4)
	)
)

(defskeleton single_token_simple
	(vars (c as rs name) (n1 n3 text))
	(defstrand client 10 (c c) (as as) (rs rs) (n1 n1) (n3 n3))
	(non-orig (privk c) (privk as) (privk rs))
	(neq (c as) (c rs) (as rs)) 
)

(defskeleton single_token_simple
	(vars (c as rs name) (n2 text))
	(defstrand authorization_server 5 (c c) (as as) (rs rs) (n2 n2))
	(non-orig (privk c) (privk as) (privk rs))
	(neq (c as) (c rs) (as rs))
)

(defskeleton single_token_simple
	(vars (c as rs name) (n4 text))
	(defstrand resource_server 5 (c c) (as as) (rs rs) (n4 n4))
	(non-orig (privk c) (privk as) (privk rs))
	(neq (c as) (c rs) (as rs)) 
)
