package eu.europa.esig.dss.validation.timestamp;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.validation.ListCRLSource;
import eu.europa.esig.dss.validation.ListOCSPSource;
import eu.europa.esig.dss.x509.CertificateToken;

public interface SignatureTimestampSource extends Serializable {
	
	List<TimestampToken> getContentTimestamps();
	
	List<TimestampToken> getSignatureTimestamps();
	
	List<TimestampToken> getTimestampsX1();
	
	List<TimestampToken> getTimestampsX2();
	
	List<TimestampToken> getArchiveTimestamps();
	
	List<TimestampToken> getDocumentTimestamps();
	
	List<TimestampToken> getAllTimestamps();
	
	/**
	 * This method allows to add an external timestamp. The given timestamp must be processed before.
	 * 
	 * @param timestamp
	 *            the timestamp token
	 */
	void addExternalTimestamp(TimestampToken timestamp);
	
	/**
	 * Returns a map between all found timestamps and their certificates
	 * @param skipLastArchiveTimestamp
	 *            in case if the last Archive Timestamp is not needed to be returned
	 * @return a map between timestamp-id and list of related {@link CertificateToken}s
	 */
	Map<String, List<CertificateToken>> getCertificateMapWithinTimestamps(boolean skipLastArchiveTimestamp);
	
	/**
	 * Returns a list of all found certificates in the timestamps
	 * @return a list of {@link CertificateToken}s
	 */
	List<CertificateToken> getCertificates();
	
	/**
	 * Returns a merged {@code ListCRLSource} between signatureCRLSource and all embedded timestamp CRL sources
	 * 
	 * @return {@link ListCRLSource}
	 */
	ListCRLSource getCommonCRLSource();
	
	/**
	 * Returns a merged {@code ListOCSPSource} between signatureOCSPSource and all embedded timestamp OCSP sources
	 * 
	 * @return {@link ListOCSPSource}
	 */
	ListOCSPSource getCommonOCSPSource();

}
