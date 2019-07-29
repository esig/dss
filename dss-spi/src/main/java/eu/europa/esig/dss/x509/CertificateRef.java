package eu.europa.esig.dss.x509;

import java.io.Serializable;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;

public class CertificateRef implements Serializable {

	private static final long serialVersionUID = -325165164194282066L;
	
	private Digest certDigest;
	private IssuerSerialInfo issuerInfo;
	private CertificateRefOrigin origin;
	
	private String dssId;

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
	
	public CertificateRefOrigin getOrigin() {
		return origin;
	}
	
	public void setOrigin(CertificateRefOrigin origin) {
		this.origin = origin;
	}
	
	/**
	 * Returns revocation reference {@link String} id
	 * @return {@link String} id
	 */
	public String getDSSIdAsString() {
		if (dssId == null) {
			dssId = "C-" + certDigest.getHexValue().toUpperCase();
		}
		return dssId;
	}

	@Override
	public String toString() {
		return "CertificateRef [certDigest=" + certDigest + ", issuerInfo=" + issuerInfo + ", origin=" + origin + "]";
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
		if ((origin == null && o.getOrigin() != null) || 
				(origin != null && !origin.equals(o.getOrigin()))) {
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
		result = (prime * result) + ((origin == null) ? 0 : origin.hashCode());
		return result;
	}

}
