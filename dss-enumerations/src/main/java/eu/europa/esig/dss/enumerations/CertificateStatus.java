package eu.europa.esig.dss.enumerations;

public enum CertificateStatus {

	/**
	 * The certificate is not revoked
	 */
	GOOD,

	/**
	 * The certificate is revoked
	 */
	REVOKED,

	/**
	 * The certificate status is not known
	 */
	UNKNOWN;

	public boolean isGood() {
		return GOOD == this;
	}

	public boolean isRevoked() {
		return REVOKED == this;
	}

	public boolean isKnown() {
		return UNKNOWN != this;
	}

}
