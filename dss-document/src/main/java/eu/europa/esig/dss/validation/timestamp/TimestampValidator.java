package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CertificatePoolSharer;
import eu.europa.esig.dss.validation.DocumentValidator;

public interface TimestampValidator extends DocumentValidator, CertificatePoolSharer {
	
	/**
	 * Returns the TimestampToken from the document
	 * 
	 * @return the timestamp token
	 */
	TimestampToken getTimestamp();

	/**
	 * The timestamped data
	 * 
	 * @param document
	 *                 the data which was timestamped
	 */
	void setDetachedContent(DSSDocument document);

//	/**
//	 * Returns a map of detached timestamps and their signatureScopes
//	 * 
//	 * @return a map between {@link TimestampToken}s and lists of
//	 *         {@link SignatureScope}s
//	 */
//	Map<TimestampToken, List<SignatureScope>> getTimestamps();
	
}
