package eu.europa.esig.dss.jades.validation;

import java.util.Objects;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import eu.europa.esig.dss.model.DSSException;

public class CustomJsonWebSignature extends JsonWebSignature {

	public CustomJsonWebSignature() {}
	
	public CustomJsonWebSignature(String header, String payload, String signature) {
		Objects.requireNonNull(header, "Header part cannot be null");
		Objects.requireNonNull(payload, "Payload part cannot be null");
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

	public byte[] getSignatureValue() {
		return super.getSignature();
	}

}
