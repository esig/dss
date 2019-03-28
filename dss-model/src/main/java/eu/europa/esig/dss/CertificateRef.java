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

}
