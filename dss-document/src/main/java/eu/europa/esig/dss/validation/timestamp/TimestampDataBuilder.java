package eu.europa.esig.dss.validation.timestamp;

public interface TimestampDataBuilder {
	
	/**
	 * Returns the content timestamp data (timestamped or to be).
	 *
	 * @param timestampToken
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getContentTimestampData(final TimestampToken timestampToken);

	/**
	 * Returns the data (signature value) that was timestamped by the SignatureTimeStamp for the given timestamp.
	 *
	 * @param timestampToken
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getSignatureTimestampData(final TimestampToken timestampToken);

	/**
	 * Returns the data to be time-stamped. The data contains the digital signature (XAdES example: ds:SignatureValue
	 * element), the signature time-stamp(s) present in the AdES-T form, the certification path references and the
	 * revocation status references.
	 *
	 * @param timestampToken
	 *            {@code TimestampToken} or null during the creation process
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getTimestampX1Data(final TimestampToken timestampToken);

	/**
	 * Returns the data to be time-stamped which contains the concatenation of CompleteCertificateRefs and
	 * CompleteRevocationRefs elements (XAdES example).
	 *
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getTimestampX2Data(final TimestampToken timestampToken);
	
	/**
	 * Archive timestamp seals the data of the signature in a specific order. We need to retrieve the data for each
	 * timestamp.
	 *
	 * @param timestampToken
	 *            null when adding a new archive timestamp
	 * @return {@code byte} array representing the canonicalized data to be timestamped
	 */
	byte[] getArchiveTimestampData(final TimestampToken timestampToken);

}
