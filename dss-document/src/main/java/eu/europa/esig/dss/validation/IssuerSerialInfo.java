package eu.europa.esig.dss.validation;

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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((issuerName == null) ? 0 : issuerName.hashCode());
		result = (prime * result) + ((serialNumber == null) ? 0 : serialNumber.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof IssuerSerialInfo)) {
			return false;
		}
		IssuerSerialInfo other = (IssuerSerialInfo) obj;
		if ((issuerName == null && other.getIssuerName() != null) || 
				(issuerName != null && !issuerName.equals(other.getIssuerName()))) {
			return false;
		}
		if ((serialNumber == null && other.getSerialNumber() != null) || 
				(serialNumber != null && !serialNumber.equals(other.getSerialNumber()))) {
			return false;
		}
		return true;
	}

}
