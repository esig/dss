package eu.europa.esig.dss.validation;

import java.math.BigInteger;

/**
 * This class represents SignerInfo content for instances found in CAdES CMS Signed Data
 * 
 */
public class SignerInfo {
	
	private final String issuer;
	private final BigInteger serialNumber;
	
	private boolean validated; // the framework validates only the first SignerInfo
	
	public SignerInfo(final String issuer, final BigInteger serialNumber) {
		this.issuer = issuer;
		this.serialNumber = serialNumber;
	}
	
	public String getIssuer() {
		return issuer;
	}
	
	public BigInteger getSerialNumber() {
		return serialNumber;
	}
	
	public boolean isValidated() {
		return validated;
	}
	
	public void setValidated(boolean validated) {
		this.validated = validated;
	}

}
