package eu.europa.esig.dss.enumerations;

/**
 * Represents JWS types defined in RFC 7515, 3. JSON Web Signature (JWS) Overview
 *
 */
public enum JWSSerializationType {
	
	/**
	 * 3.1.  JWS Compact Serialization Overview
	 * 
	 * In the JWS Compact Serialization, no JWS Unprotected Header is used.
	 * In this case, the JOSE Header and the JWS Protected Header are the
	 * same.
	 * In the JWS Compact Serialization, a JWS is represented as the
	 * concatenation:
	 * 
	 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
	 * BASE64URL(JWS Payload) || '.' ||
	 * BASE64URL(JWS Signature)
	 */
	COMPACT_SERIALIZATION,
	
	/**
	 * 3.2.  JWS JSON Serialization Overview
	 * 
	 * In the JWS JSON Serialization, one or both of the JWS Protected
	 * Header and JWS Unprotected Header MUST be present.  In this case, the
	 * members of the JOSE Header are the union of the members of the JWS
	 * Protected Header and the JWS Unprotected Header values that are
	 * present.
	 * 
	 * In the JWS JSON Serialization, a JWS is represented as a JSON object
	 * containing some or all of these four members:
	 * 
	 * - "protected", with the value BASE64URL(UTF8(JWS Protected Header))
	 * - "header", with the value JWS Unprotected Header
	 * - "payload", with the value BASE64URL(JWS Payload)
	 * - "signature", with the value BASE64URL(JWS Signature)
	 * 
	 * The three base64url-encoded result strings and the JWS Unprotected
	 * Header value are represented as members within a JSON object.
	 * 
	 * The JWS JSON Serialization can also represent multiple signature and/or MAC
	 * values, rather than just one.
	 */
	JSON_SERIALIZATION;

}
