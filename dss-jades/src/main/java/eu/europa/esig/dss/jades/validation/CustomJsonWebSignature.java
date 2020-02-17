package eu.europa.esig.dss.jades.validation;

import org.jose4j.jws.JsonWebSignature;

public class CustomJsonWebSignature extends JsonWebSignature {
	
	@Override
	public String getEncodedHeader() {
		return super.getEncodedHeader();
	}
	
	public byte[] getSignatureValue() {
		return super.getSignature();
	}

}
