/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Extension of a JSON web Signature according to RFC 7515
 */
public class JWS extends JsonWebSignature implements Serializable {

	private static final long serialVersionUID = -3465226120689258742L;

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
		// empty
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
			throw new IllegalInputException("Unable to instantiate a compact JWS", e);
		}
	}

	@Override
	public String getEncodedHeader() {
		return super.getEncodedHeader();
	}
	
	/**
	 * Sets payload binaries depending on the 'b64' header's value
	 * 
	 * @param payload a byte array representing a payload (unencoded or encoded)
	 */
	public void setPayloadOctets(byte[] payload) {
		// see JsonWebSignature.setCompactSerializationParts(parts)
		if (isRfc7797UnencodedPayload()) {
            setPayloadBytes(payload);
        } else {
            setEncodedPayload(new String(payload));
        }
	}
	
	/**
	 * Returns payload string based on a 'b64' value in the protected header
	 * (The actual signed payload value)
	 *
	 * @return {@link String} payload to be signed
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

	/**
	 * Sets the protected header
	 *
	 * @param protectedBase64Url {@link String} base64url encoded protected header
	 * @throws JoseException if a format exception occurs
	 */
	public void setProtected(String protectedBase64Url) throws JoseException {
		super.setEncodedHeader(protectedBase64Url);
	}

	/**
	 * Gets unprotected header map
	 *
	 * @return unprotected header map
	 */
	public Map<String, Object> getUnprotected() {
		return unprotected;
	}

	/**
	 * Sets the unprotected header
	 *
	 * @param unprotected the unprotected header map
	 */
	public void setUnprotected(Map<String, Object> unprotected) {
		this.unprotected = unprotected;
	}

	/**
	 * Gets the {@code JWSJsonSerializationObject}
	 *
	 * @return {@link JWSJsonSerializationObject}
	 */
	public JWSJsonSerializationObject getJwsJsonSerializationObject() {
		return jwsJsonSerializationObject;
	}

	/**
	 * Sets the {@code JWSJsonSerializationObject}
	 *
	 * @param jwsJsonSerializationObject {@link JWSJsonSerializationObject}
	 */
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

	@Override
	protected void checkCrit() throws JoseException {
		// separate structure validation and cryptographic check
		// (see eu.europa.esig.dss.jades.validation.JAdESBaselineRequirementsChecker)
	}

	/**
	 * Returns a protected header value with the {@code key}
	 *
	 * @param key {@link String}
	 * @return {@link String} value if present, empty string otherwise
	 */
	public String getProtectedHeaderValueAsString(String key) {
		return DSSJsonUtils.toString(getHeaders().getObjectHeaderValue(key), key);
	}

	/**
	 * Returns a protected header value with the {@code key}
	 *
	 * @param key {@link String}
	 * @return {@link Number} value if present, NULL otherwise
	 */
	public Number getProtectedHeaderValueAsNumber(String key) {
		return DSSJsonUtils.toNumber(getHeaders().getObjectHeaderValue(key), key);
	}

	/**
	 * Returns a protected header value with the {@code key}
	 *
	 * @param key {@link String}
	 * @return {@link Map} value if present, empty map otherwise
	 */
	public Map<?, ?> getProtectedHeaderValueAsMap(String key) {
		return DSSJsonUtils.toMap(getHeaders().getObjectHeaderValue(key), key);
	}

	/**
	 * Returns a protected header value with the {@code key}
	 *
	 * @param key {@link String}
	 * @return {@link List} value if present, empty list otherwise
	 */
	public List<?> getProtectedHeaderValueAsList(String key) {
		return DSSJsonUtils.toList(getHeaders().getObjectHeaderValue(key), key);
	}

}
