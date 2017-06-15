package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.DSSDocument;

public interface TimestampValidator {

	/**
	 * Retrieves the time-stamp token
	 * 
	 * @return
	 */
	TimestampToken getTimestamp();

	/**
	 * Provides a {@code CertificateVerifier} to be used during the validation process.
	 *
	 * @param certVerifier
	 *            {@code CertificateVerifier}
	 */
	void setCertificateVerifier(final CertificateVerifier certVerifier);

	/**
	 * Sets the {@code DSSDocument} containing the time-stamped content.
	 *
	 * @param timestampedDocument
	 *            the {@code DSSDocument} to set
	 */
	void setTimestampedData(DSSDocument timestampedData);

}
