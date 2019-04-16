package eu.europa.esig.dss;

public class CertificateRef {

	private Digest certDigest;
	private IssuerSerialInfo issuerInfo;

	public Digest getCertDigest() {
		return certDigest;
	}

	public void setCertDigest(Digest certDigest) {
		this.certDigest = certDigest;
	}

	public IssuerSerialInfo getIssuerInfo() {
		return issuerInfo;
	}

	public void setIssuerInfo(IssuerSerialInfo issuerInfo) {
		this.issuerInfo = issuerInfo;
	}

	@Override
	public String toString() {
		return "CertificateRef [certDigest=" + certDigest + ", issuerInfo=" + issuerInfo + "]";
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof CertificateRef)) {
			return false;
		}
		CertificateRef o = (CertificateRef) obj;
		if ((certDigest == null && o.getCertDigest() != null) || 
				(certDigest != null && !certDigest.equals(o.getCertDigest()))) {
			return false;
		}
		if ((issuerInfo == null && o.getIssuerInfo() != null) || 
				(issuerInfo != null && !issuerInfo.equals(o.getIssuerInfo()))) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((certDigest == null) ? 0 : certDigest.hashCode());
		result = (prime * result) + ((issuerInfo == null) ? 0 : issuerInfo.hashCode());
		return result;
	}

}
