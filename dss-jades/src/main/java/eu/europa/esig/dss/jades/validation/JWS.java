package eu.europa.esig.dss.jades.validation;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.model.DSSException;

public class JWS extends JsonWebSignature {

	/**
	 * The unprotected header map
	 */
	private Map<String, Object> unprotected;
	
	/**
	 * The parent {@code JWSJsonSerializationObject}
	 */
	private JWSJsonSerializationObject jwsJsonSerializationObject;

	/**
	 * The default constructor creating an empty JsonWebSignature
	 */
	public JWS() {
	}

	/**
	 * The constructor to instantiate a JWSCompactSerialization objects (RFC 7515)
	 * 
	 * @param parts an array of String with the header, optional payload and
	 * 				the signature
	 */
	public JWS(String[] parts) {
		Objects.requireNonNull(parts, "Parts part cannot be null");

		try {
			setCompactSerializationParts(parts);
		} catch (JoseException e) {
			throw new DSSException("Unable to instantiate a compact JWS", e);
		}
	}

	@Override
	public String getEncodedHeader() {
		return super.getEncodedHeader();
	}
	
	/**
	 * Sets a detached payload binaries
	 * 
	 * @param payload a byte array representing a payload
	 */
	public void setDetachedPayload(byte[] payload) {
		// see JsonWebSignature.setCompactSerializationParts(parts)
		if (isRfc7797UnencodedPayload()) {
            setPayloadBytes(payload);
        } else {
            setEncodedPayload(JAdESUtils.toBase64Url(payload));
        }
	}
	
	/**
	 * Returns payload string based on a 'b64' value in the protected header
	 * (The actual signed payload value)
	 */
	public String getSignedPayload() {
		if (isRfc7797UnencodedPayload()) {
            return getUnverifiedPayload();
        } else {
            return getEncodedPayload();
        }
	}
	
	/**
	 * Checks if the signature's payload is 'b64' unencoded (see RFC 7797)
	 * 
	 * @return TRUE if 'b64' is present and set to false, FALSE otherwise
	 */
	@Override
	public boolean isRfc7797UnencodedPayload() {
		return super.isRfc7797UnencodedPayload();
	}

	/**
	 * Returns SignatureValue bytes
	 * 
	 * @return byte array representing a signature value
	 */
	public byte[] getSignatureValue() {
		return super.getSignature();
	}

	@Override
	public void setSignature(byte[] signature) {
		super.setSignature(signature);
	}

	public void setProtected(String protectedBase64Url) throws JoseException {
		super.setEncodedHeader(protectedBase64Url);
	}

	public void setUnprotected(Map<String, Object> unprotected) {
		this.unprotected = unprotected;
	}

	public Map<String, Object> getUnprotected() {
		return unprotected;
	}

	public JWSJsonSerializationObject getJwsJsonSerializationObject() {
		return jwsJsonSerializationObject;
	}

	public void setJwsJsonSerializationObject(JWSJsonSerializationObject jwsJsonSerializationObject) {
		this.jwsJsonSerializationObject = jwsJsonSerializationObject;
	}
	
	/**
	 * Sets values of the 'crit' header that must be known and proceeded
	 * 
	 * @param knownCriticalHeaders a collection of supported {@link String} headers
	 */
	public void setKnownCriticalHeaders(Collection<String> knownCriticalHeaders) {
		String[] headersArray = knownCriticalHeaders.toArray(new String[knownCriticalHeaders.size()]);
		super.setKnownCriticalHeaders(headersArray);
	}

}
