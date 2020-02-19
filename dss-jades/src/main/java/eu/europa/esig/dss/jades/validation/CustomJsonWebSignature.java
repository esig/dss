package eu.europa.esig.dss.jades.validation;

import java.util.Objects;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.model.DSSException;

public class CustomJsonWebSignature extends JsonWebSignature {
	
	/**
	 * The default constructor creating an empty JWS object
	 */
	public CustomJsonWebSignature() {
	}

	/**
	 * The constructor to instantiate a JSON signature object
	 * 
	 * @param header {@link String} base64Url encoded header
	 * @param payload {@link String} base64Url encoded payload
	 * @param signature {@link String} base64Url encoded signature
	 */
	public CustomJsonWebSignature(String header, String payload, String signature) {
		Objects.requireNonNull(header, "Header part cannot be null");
		Objects.requireNonNull(payload, "Payload part cannot be null"); // TODO: can be empty for a detached sig ?
		Objects.requireNonNull(signature, "Signature part cannot be null");

		try {
			setCompactSerializationParts(new String[] { header, payload, signature });
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
