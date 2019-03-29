package eu.europa.esig.dss;

import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

public class IssuerSerialInfo {

	private X500Principal issuerName;
	private BigInteger serialNumber;

	public X500Principal getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(X500Principal name) {
		this.issuerName = name;
	}

	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(BigInteger serialNumber) {
		this.serialNumber = serialNumber;
	}

	@Override
	public String toString() {
		return "IssuerSerialInfo [issuerName=" + issuerName + ", serialNumber=" + serialNumber + "]";
	}

}
