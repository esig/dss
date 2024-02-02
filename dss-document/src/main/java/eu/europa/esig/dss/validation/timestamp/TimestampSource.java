/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.io.Serializable;
import java.util.List;

/**
 * The interface for handling validation data extracted from timestamps
 *
 */
public interface TimestampSource extends Serializable {

	/**
	 * Returns a list of incorporated content timestamps
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getContentTimestamps();

	/**
	 * Returns a list of incorporated signature timestamps
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getSignatureTimestamps();

	/**
	 * Returns a list of incorporated SigAndRefs timestamps
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getTimestampsX1();

	/**
	 * Returns a list of incorporated RefsOnly timestamps
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getTimestampsX2();

	/**
	 * Returns a list of incorporated archive timestamps
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getArchiveTimestamps();

	/**
	 * Returns a list of incorporated document timestamps (PAdES only)
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getDocumentTimestamps();

	/**
	 * Returns a list of detached timestamps (used in ASiC with CAdES)
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getDetachedTimestamps();

	/**
	 * Returns a list of all incorporated timestamps
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getAllTimestamps();
	
	/**
	 * This method allows to add an external timestamp. The given timestamp must be processed before.
	 * 
	 * @param timestamp
	 *            {@link TimestampToken} the timestamp token
	 */
	void addExternalTimestamp(TimestampToken timestamp);

	/**
	 * Returns a list of evidence records embedded to a signature document
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	List<EvidenceRecord> getEmbeddedEvidenceRecords();

	/**
	 * Returns a list of evidence records detached from a signature document
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	List<EvidenceRecord> getDetachedEvidenceRecords();

	/**
	 * Returns a list of all evidence records associated with the signature
	 *
	 * @return a list of {@link EvidenceRecord}s
	 */
	List<EvidenceRecord> getAllEvidenceRecords();

	/**
	 * This method allows to add an external evidence record. The given evidence record must be processed before.
	 *
	 * @param evidenceRecord
	 *            {@link EvidenceRecord} the evidence record covering the signature file
	 */
	void addExternalEvidenceRecord(EvidenceRecord evidenceRecord);
	
	/**
	 * Returns a merged {@code ListCertificateSource} of all embedded timestamp certificate sources
	 * 
	 * @return {@link ListCertificateSource}
	 */
	ListCertificateSource getTimestampCertificateSources();

	/**
	 * Returns a merged {@code ListCertificateSource} of all embedded timestamp
	 * certificate sources except the latest Archive Timestamp
	 * 
	 * @return {@link ListCertificateSource}
	 */
	ListCertificateSource getTimestampCertificateSourcesExceptLastArchiveTimestamp();

	/**
	 * Returns a list of all {@code TimestampToken}s except the last archive timestamp
	 *
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getAllTimestampsExceptLastArchiveTimestamp();

	/**
	 * Returns a merged {@code ListRevocationSource} of all embedded timestamp CRL
	 * sources
	 * 
	 * @return {@link ListRevocationSource}
	 */
	ListRevocationSource<CRL> getTimestampCRLSources();
	
	/**
	 * Returns a merged {@code ListRevocationSource} of all embedded timestamp OCSP
	 * sources
	 * 
	 * @return {@link ListRevocationSource}
	 */
	ListRevocationSource<OCSP> getTimestampOCSPSources();
	
	/**
	 * Returns a list of {@link TimestampedReference}s for all tokens embedded into unsigned properties of the signature
	 * 
	 * @return a list of {@link TimestampedReference}s
	 */
	List<TimestampedReference> getUnsignedPropertiesReferences();
	
	/**
	 * Returns a list of {@link TimestampedReference}s obtained from the {@code signatureScopes}
	 * 
	 * @return list of {@link TimestampedReference}s
	 */
	List<TimestampedReference> getSignerDataReferences();
	
	/**
	 * Checks if a tokenId with the given Id is covered by the timestamp source
	 * 
	 * @param tokenId {@link String} Id of the token to check
	 * @param objectType {@link TimestampedObjectType} defining the type of the token
	 * @return TRUE if the token if covered by the timestamp source, FALSE otherwise
	 */
	boolean isTimestamped(String tokenId, TimestampedObjectType objectType);

}
