(herald "Grant Negotiation and Authorization Protocol"
	(limit 5000)
	(comment "This protocol allows a piece of software, the client instance, to request delegated authorization to resource servers and to request direct information"))

(defprotocol gnap_simple basic
	(defrole client
		(vars (c as rs name) (access uri c_token acess_token_1 acess_token_2 rights data))
		(trace
			; When sending a non-continuation request to the AS, the client instance MUST identify itself by including the client field of the
			; request and by signing the request as described in Section 7.3. Note that for a continuation request (Section 5), the client instance is
			; identified by its association with the request being continued and so this field is not sent under those circumstances.
			
			; client (object / string) Describes the client instance that is making this request, including the key that the client instance
			; will use to protect this request and any continuation requests at the AS and any user-facing information about the client instance
			; used in interactions.

			; The client instance determines what access is needed and which AS to approach for access.
			(send (enc c access (ltk c as))) ; client requests access at the AS
			(recv (enc uri c_token (ltk c as))) ; receives continuation response from AS
			
			; The continuation access token is initially bound to the same key and method the client instance used to make the initial request. As a
			; consequence, when the client instance makes any calls to the continuation URL, the client instance MUST present the continuation
			; access token as described in Section 7.2 and present proof of the client instance's key (or its most recent rotation) by signing the
			; request as described in Section 7.3.			
			(send (enc c_token (ltk c as))) ; The client instance continues the grant at the AS (Section 5).
			(recv (enc acess_token_1 rights (ltk c as))) ; receives access token from AS
			
			; If the flags field does not contain the bearer flag and the key is absent, the access token MUST be sent using the same key and proofing
			; mechanism that the client instance used in its initial request (or its most recent rotation).			
			(send (enc acess_token_1 (ltk c rs))) ; The client instance uses the access token (Section 7.2) to call the RS.
			
			; The client instance calls the RS (Section 7.2) using the access token until the RS or client instance determine that the token is no longer valid.
			; ^^^ Should this be modeled? If so how? ^^^
			
			; The client instance makes an HTTP POST to the token management URI, sending the access token in the appropriate header and signing the
			; request with the appropriate key.
			; If the access token has expired, the AS SHOULD honor the rotation request to the token management URL since it is likely that the
			; client instance is attempting to refresh the expired token. An AS MUST NOT honor a rotation request for an access token that has 
			; been revoked, either by the AS or by the client instance through the token management URI (Section 6.2).
			
			(send (enc acess_token_1 (ltk c as))) ; When the token no longer works, the client instance fetches an updated access token (Section 6.1) based on the rights granted in line 26.
			(recv (enc acess_token_2 (ltk c as))) ; Receives new access token
			(send (enc acess_token_2 (ltk c rs))) ; The client instance uses the new access token (Section 7.2) to call the RS.
			
			; If the client instance wishes to revoke the access token proactively, such as when a user indicates to the client instance that they no
			; longer wish for it to have access or the client instance application
			; detects that it is being uninstalled, the client instance can use the
			; token management URI to indicate to the AS that the AS should
			; invalidate the access token for all purposes.
			
			; The client instance makes an HTTP DELETE request to the token management URI, presenting the access token and signing the request
			; with the appropriate key.
			(send (enc acess_token_2 (ltk c as))) ; The client instance disposes of the token (Section 6.2) once the client instance has completed its access of the RS and no longer needs the token.
		)
	)
	(defrole authorization_server
		(vars (c as name) (access uri c_token acess_token_1 acess_token_2 rights data))
		(trace
			(recv (enc c access (ltk c as))) ; AS processes request and determines what is needed to fulfill the request
			
			; continue (object) Indicates that the client instance can continue the request by making one or more continuation requests.
			
			; This field contains a JSON object with the following properties: (wait not included)
			
				; uri (string) REQUIRED. The URI at which the client instance can make continuation requests. This URI MAY vary per request, or MAY
				; be stable at the AS. The client instance MUST use this value exactly as given when making a continuation request
				
				; access_token (object) REQUIRED. A unique access token for continuing the request, called the "continuation access token".
				; The value of this property MUST be in the format specified in Section 3.2.1. This access token MUST be bound to the client
				; instance's key used in the request and MUST NOT be a bearer token. As a consequence, the flags array of this access token MUST NOT
				; contain the string bearer and the key field MUST be omitted. The client instance MUST present the continuation access token in all
				; requests to the continuation URI
				
			; instance_id (string) An identifier this client instance can use to identify itself when making future requests. Section 3.5

			; If desired, the AS MAY also generate and return an instance identifier dynamically to the client instance in the response to
			; facilitate multiple interactions with the same client instance over time. The client instance SHOULD use this instance identifier in
			; future requests in lieu of sending the associated data values in the client field.
			
			
			; To enable this ongoing negotiation, the AS provides a continuation API to the client software. The AS returns a continue field in the
			; response (Section 3.1) that contains information the client instance needs to access this API, including a URI to access as well as a
			; continuation access token to use during the requests.
			
			(send (enc uri c_token (ltk c as))) ; AS sends its response to client instance
			(recv (enc c_token (ltk c as))) ; receives continuation token from client
			
			; If the client instance has requested a single access token and the AS has granted that access token, the AS responds with the
			; "access_token" field. The value of this field is an object with the following properties: (only REQUIRED shown)
			
				; value (string) REQUIRED. The value of the access token as a string. The value is opaque to the client instance. The value SHOULD be
				; limited to ASCII characters to facilitate transmission over HTTP headers within other protocols without requiring additional 
				; encoding.
			(send (enc acess_token_1 rights (ltk c as))) ; If the AS determines that access can be granted, it returns a response to the client instance (Section 3) 
			; including an access token (Section 3.2) for calling the RS and any directly returned information (Section 3.4) about the RO
			
			(recv (enc acess_token_1 (ltk c as))) ; The AS receives the request for refreshing the expired token
			(send (enc acess_token_2 (ltk c as))) ; The AS issues a new access token (Section 3.2) to the client instance.
			(recv (enc acess_token_2 (ltk c as))) ; Receives request to delete the access token
		)
	)
	(defrole resource_server
		(vars (c rs name) (acess_token_1 acess_token_2 data))
		(trace
			(recv (enc acess_token_1 (ltk c rs))) ; The RS determines if the token is sufficient for the request by examining the token.
			(recv (enc acess_token_2 (ltk c rs))) ; The RS determines if the new token is sufficient for the request.
		)
	)
)

(defskeleton gnap_simple
  (vars (c as rs name) (access data))
  (defstrand client 9 (c c) (as as) (rs rs))
  (non-orig (ltk c as) (ltk c rs))
  (comment "")
)
