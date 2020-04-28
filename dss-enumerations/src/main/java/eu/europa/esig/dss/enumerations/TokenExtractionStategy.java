package eu.europa.esig.dss.enumerations;

public enum TokenExtractionStategy {

	/**
	 * Extract certificates, timestamps and revocation data
	 */
	EXTRACT_ALL(true, true, true),

	/**
	 * Extract certificates
	 */
	EXTRACT_CERTIFICATES_ONLY(true, false, false),

	/**
	 * Extract timestamps
	 */
	EXTRACT_TIMESTAMPS_ONLY(false, true, false),

	/**
	 * Extract revocation data
	 */
	EXTRACT_REVOCATION_DATA_ONLY(false, false, true),

	/**
	 * Extract certificates and timestamps
	 */
	EXTRACT_CERTIFICATES_AND_TIMESTAMPS(true, true, false),

	/**
	 * Extract certificates and revocation data
	 */
	EXTRACT_CERTIFICATES_AND_REVOCATION_DATA(true, false, true),

	/**
	 * Extract timestamps and revocation data
	 */
	EXTRACT_TIMESTAMPS_AND_REVOCATION_DATA(false, true,
			true),

	/**
	 * Extract nothing
	 */
	NONE(false, false, false);

	private final boolean certificate;
	private final boolean timestamp;
	private final boolean revocationData;

	TokenExtractionStategy(boolean certificate, boolean timestamp, boolean revocationData) {
		this.certificate = certificate;
		this.timestamp = timestamp;
		this.revocationData = revocationData;
	}

	/**
	 * This method returns true if the certificate extraction is enabled
	 * 
	 * @return true if certificates need to be extracted
	 */
	public boolean isCertificate() {
		return certificate;
	}

	/**
	 * This method returns true if the timestamp extraction is enabled
	 * 
	 * @return true if timestamps need to be extracted
	 */
	public boolean isTimestamp() {
		return timestamp;
	}

	/**
	 * This method returns true if the revocation data extraction is enabled
	 * 
	 * @return true if revocation data need to be extracted
	 */
	public boolean isRevocationData() {
		return revocationData;
	}

	/**
	 * Returns the enumeration value depending on parameters
	 * 
	 * @param certificate    true if certificates need to be extracted
	 * @param timestamp      true if timestamps need to be extracted
	 * @param revocationData true if revocation data need to be extracted
	 * @return
	 */
	public static TokenExtractionStategy fromParameters(boolean certificate, boolean timestamp, boolean revocationData) {
		for (TokenExtractionStategy value : TokenExtractionStategy.values()) {
			if ((certificate == value.certificate) && (timestamp == value.timestamp) && (revocationData == value.revocationData)) {
				return value;
			}
		}
		return TokenExtractionStategy.NONE;
	}

}
