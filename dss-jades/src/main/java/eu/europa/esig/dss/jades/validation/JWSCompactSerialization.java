package eu.europa.esig.dss.jades.validation;

import java.util.Objects;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.model.DSSException;

public class JWSCompactSerialization extends JsonWebSignature {

	/**
	 * The default constructor creating an empty JWS Compact Serialization object
	 * according to RFC 7515
	 */
	public JWSCompactSerialization() {
	}

	/**
	 * The constructor to instantiate a JWSCompactSerialization objects (RFC 7515)
	 * 
	 * @param parts an array of String with the header, optional payload and
	 * 				the signature
	 */
	public JWSCompactSerialization(String[] parts) {
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
	 * Returns SignatureValue bytes
	 * 
	 * @return byte array representing a signature value
	 */
	public byte[] getSignatureValue() {
		return super.getSignature();
	}

}
