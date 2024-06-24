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
package eu.europa.esig.dss.spi.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.DefaultAdvancedSignature;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.tsp.TimestampCRLSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampOCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Contains a set of {@link TimestampToken}s found in a {@link DefaultAdvancedSignature} object
 */
@SuppressWarnings("serial")
public abstract class AbstractTimestampSource {

	/**
	 * Default constructor
	 */
	protected AbstractTimestampSource() {
		// empty
	}

	/**
	 * Adds {@code referenceToAdd} to {@code referenceList} without duplicates
	 *
	 * @param referenceList - list of {@link TimestampedReference}s to be extended
	 * @param referenceToAdd - {@link TimestampedReference} to be added
	 */
	protected void addReference(List<TimestampedReference> referenceList, TimestampedReference referenceToAdd) {
		addReferences(referenceList, Arrays.asList(referenceToAdd));
	}

	/**
	 * Adds a reference for the given identifier and category
	 *
	 * @param referenceList - list of {@link TimestampedReference}s to be extended
	 * @param identifier    - {@link Identifier} to be added
	 * @param category      - {@link TimestampedObjectType} to be added
	 */
	protected void addReference(List<TimestampedReference> referenceList, Identifier identifier,
								TimestampedObjectType category) {
		addReferences(referenceList, Arrays.asList(new TimestampedReference(identifier.asXmlId(), category)));
	}

	/**
	 * Adds {@code referencesToAdd} to {@code referenceList} without duplicates
	 *
	 * @param referenceList - list of {@link TimestampedReference}s to be extended
	 * @param referencesToAdd - {@link TimestampedReference}s to be added
	 */
	protected void addReferences(List<TimestampedReference> referenceList, List<TimestampedReference> referencesToAdd) {
		DSSUtils.enrichCollection(referenceList, referencesToAdd);
	}

	/**
	 * Incorporates all references from the given {@code timestampToken}
	 *
	 * @param timestampToken a {@link TimestampToken} to extract values from
	 * @param certificateSource {@link ListCertificateSource} merged certificate source
	 * @param crlSource {@link ListRevocationSource} merged CRL source
	 * @param ocspSource {@link ListRevocationSource} merged OCSP source
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getReferencesFromTimestamp(TimestampToken timestampToken,
																	ListCertificateSource certificateSource,
																	ListRevocationSource<CRL> crlSource,
																	ListRevocationSource<OCSP> ocspSource) {
		List<TimestampedReference> references = new ArrayList<>();
		addReference(references, new TimestampedReference(timestampToken.getDSSIdAsString(), TimestampedObjectType.TIMESTAMP));
		addReferences(references, timestampToken.getTimestampedReferences());
		addReferences(references, getEncapsulatedValuesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource));
		return references;
	}

	/**
	 * Gets a list of all validation data embedded to the {@code timestampedTimestamp}
	 *
	 * @param timestampedTimestamp {@link TimestampToken} to extract embedded values from
	 * @param certificateSource {@link ListCertificateSource} merged certificate source
	 * @param crlSource {@link ListRevocationSource} merged CRL source
	 * @param ocspSource {@link ListRevocationSource} merged OCSP source
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getEncapsulatedValuesFromTimestamp(TimestampToken timestampedTimestamp,
																			ListCertificateSource certificateSource,
																			ListRevocationSource<CRL> crlSource,
																			ListRevocationSource<OCSP> ocspSource) {
		final List<TimestampedReference> references = new ArrayList<>();

		final TimestampCertificateSource timestampCertificateSource = timestampedTimestamp.getCertificateSource();
		addReferences(references, createReferencesForCertificates(timestampCertificateSource.getCertificates()));
		addReferences(references, createReferencesForCertificateRefs(timestampCertificateSource.getAllCertificateRefs(),
				timestampCertificateSource, certificateSource));

		final TimestampCRLSource timestampCRLSource = timestampedTimestamp.getCRLSource();
		addReferences(references, createReferencesForCRLBinaries(timestampCRLSource.getAllRevocationBinaries()));
		addReferences(references, createReferencesForCRLRefs(timestampCRLSource.getAllRevocationReferences(),
				timestampCRLSource, crlSource));

		final TimestampOCSPSource timestampOCSPSource = timestampedTimestamp.getOCSPSource();
		addReferences(references, createReferencesForOCSPBinaries(timestampOCSPSource.getAllRevocationBinaries(), certificateSource));
		addReferences(references, createReferencesForOCSPRefs(timestampOCSPSource.getAllRevocationReferences(),
				timestampOCSPSource, certificateSource, ocspSource));

		return references;
	}

	/**
	 * Creates a list of {@link TimestampedReference}s from a given list of {@code SignatureScope}s
	 *
	 * @param signatureScopes a list of {@link SignatureScope} to create {@link TimestampedReference}s for
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getSignerDataTimestampedReferences(List<SignatureScope> signatureScopes) {
		final List<TimestampedReference> references = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (SignatureScope signatureScope : signatureScopes) {
				addReference(references, new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
				if (Utils.isCollectionNotEmpty(signatureScope.getChildren())) {
					addReferences(references, getSignerDataTimestampedReferences(signatureScope.getChildren()));
				}
			}
		}
		return references;
	}

	/**
	 * Creates a list of {@code TimestampedReference}s for the provided list of {@code certificates}
	 *
	 * @param certificates collection of {@link CertificateToken}s
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForCertificates(Collection<CertificateToken> certificates) {
		final List<TimestampedReference> references = new ArrayList<>();
		for (CertificateToken certificateToken : certificates) {
			addReference(references, createReferenceForCertificate(certificateToken));
		}
		return references;
	}

	/**
	 * Creates a {@code TimestampedReference} for the provided {@code CertificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @return {@link TimestampedReference}
	 */
	protected TimestampedReference createReferenceForCertificate(CertificateToken certificateToken) {
		return createReferenceForIdentifier(certificateToken.getDSSId(), TimestampedObjectType.CERTIFICATE);
	}

	/**
	 * Creates a list of {@code TimestampedReference}s from the identifiers of a given type
	 *
	 * @param identifiers a collection of {@link Identifier}s
	 * @param timestampedObjectType {@link TimestampedObjectType} to create references with
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForIdentifiers(
			Collection<? extends Identifier> identifiers, TimestampedObjectType timestampedObjectType) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (Identifier identifier : identifiers) {
			timestampedReferences.add(createReferenceForIdentifier(identifier, timestampedObjectType));
		}
		return timestampedReferences;
	}

	/**
	 * Creates a {@code TimestampedReference} for the given identifier
	 *
	 * @param identifier {@link Identifier} to create a timestamped reference from
	 * @param timestampedObjectType {@link TimestampedObjectType} the target timestamped reference type
	 * @return {@link TimestampedReference}
	 */
	protected TimestampedReference createReferenceForIdentifier(Identifier identifier,
																TimestampedObjectType timestampedObjectType) {
		return new TimestampedReference(identifier.asXmlId(), timestampedObjectType);
	}

	/**
	 * Creates a list of {@code TimestampedReference}s from a collection of {@code CRLBinary}s
	 *
	 * @param crlBinaryIdentifiers a collection of {@link EncapsulatedRevocationTokenIdentifier}s
	 * @return a list of link {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForCRLBinaries(
			Collection<? extends EncapsulatedRevocationTokenIdentifier<CRL>> crlBinaryIdentifiers) {
		return createReferencesForIdentifiers(crlBinaryIdentifiers, TimestampedObjectType.REVOCATION);
	}

	/**
	 * Creates a list of {@code TimestampedReference}s from a collection of {@code OCSPResponseBinary}s
	 *
	 * @param ocspBinaryIdentifiers a collection of {@link EncapsulatedRevocationTokenIdentifier}s
	 * @param certificateSource {@link ListCertificateSource}
	 * @return a list of link {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForOCSPBinaries(
			Collection<? extends EncapsulatedRevocationTokenIdentifier<OCSP>> ocspBinaryIdentifiers,
			ListCertificateSource certificateSource) {
		final List<TimestampedReference> references = new ArrayList<>();
		for (EncapsulatedRevocationTokenIdentifier<OCSP> ocspIdentifier : ocspBinaryIdentifiers) {
			if (ocspIdentifier instanceof OCSPResponseBinary) {
				OCSPResponseBinary ocspResponseBinary = (OCSPResponseBinary) ocspIdentifier;
				addReferences(references, createReferencesForOCSPBinary(ocspResponseBinary, certificateSource));
			}
		}
		return references;
	}

	/**
	 * Creates a list of {@code TimestampedReference}s for a {@code OCSPResponseBinary}
	 *
	 * @param ocspResponseBinary {@link OCSPResponseBinary}
	 * @param certificateSource {@link ListCertificateSource}
	 * @return a list of link {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForOCSPBinary(OCSPResponseBinary ocspResponseBinary,
																	   ListCertificateSource certificateSource) {
		final List<TimestampedReference> references = new ArrayList<>();

		addReference(references, createReferenceForIdentifier(ocspResponseBinary, TimestampedObjectType.REVOCATION));

		final OCSPCertificateSource ocspCertificateSource = new OCSPCertificateSource(ocspResponseBinary.getBasicOCSPResp());
		addReferences(references, createReferencesForCertificates(ocspCertificateSource.getCertificates()));
		addReferences(references, createReferencesForCertificateRefs(ocspCertificateSource.getAllCertificateRefs(),
				ocspCertificateSource, certificateSource));

		return references;
	}

	/**
	 * Returns a list of timestamped references from the given collection of {@code certificateRefs}
	 *
	 * @param certificateRefs       a collection of {@link CertificateRef}s to get timestamped references from
	 * @param currentCertificateSource {@link CertificateSource} used to extract the collection of {@link CertificateRef}s
	 * @param listCertificateSource {@link ListCertificateSource} merged certificate source
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForCertificateRefs(Collection<CertificateRef> certificateRefs,
																			CertificateSource currentCertificateSource,
																			ListCertificateSource listCertificateSource) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (CertificateRef certRef : certificateRefs) {
			Set<CertificateToken> certificateTokens = currentCertificateSource.findTokensFromCertRef(certRef);
			if (Utils.isCollectionEmpty(certificateTokens)) {
				certificateTokens = listCertificateSource.findTokensFromCertRef(certRef);
			}
			if (Utils.isCollectionNotEmpty(certificateTokens)) {
				addReferences(timestampedReferences, createReferencesForCertificates(certificateTokens));
			} else {
				addReference(timestampedReferences, new TimestampedReference(certRef.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
			}
		}
		return timestampedReferences;
	}

	/**
	 * Returns a list of timestamped references from the given collection of {@code crlRefs}
	 *
	 * @param crlRefs             a collection of {@link eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef}s
	 *                            to get timestamped references from
	 * @param currentCRLSource {@link OfflineRevocationSource} used to extract CRL references
	 * @param listCRLSource {@link ListRevocationSource} merged CRL source
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForCRLRefs(Collection<? extends RevocationRef<CRL>> crlRefs,
																	OfflineRevocationSource<CRL> currentCRLSource,
																	ListRevocationSource<CRL> listCRLSource) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (RevocationRef<CRL> crlRef : crlRefs) {
			EncapsulatedRevocationTokenIdentifier<CRL> token = currentCRLSource.findBinaryForReference(crlRef);
			if (token == null) {
				token = listCRLSource.findBinaryForReference(crlRef);
			}
			if (token != null) {
				addReference(timestampedReferences, new TimestampedReference(token.asXmlId(), TimestampedObjectType.REVOCATION));
			} else {
				addReference(timestampedReferences, new TimestampedReference(crlRef.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
			}
		}
		return timestampedReferences;
	}

	/**
	 * Returns a list of timestamped references from the given collection of {@code ocspRefs}
	 *
	 * @param ocspRefs             a collection of {@link eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef}s
	 *                             to get timestamped references from
	 * @param currentOCSPSource {@link OfflineRevocationSource} used to extract the OCSP references
	 * @param listCertificateSource {@link ListCertificateSource} merged certificate source
	 * @param listOCSPSource {@link ListRevocationSource} merged OCSP source
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForOCSPRefs(Collection<? extends RevocationRef<OCSP>> ocspRefs,
																	 OfflineRevocationSource<OCSP> currentOCSPSource,
																	 ListCertificateSource listCertificateSource,
																	 ListRevocationSource<OCSP> listOCSPSource) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (RevocationRef<OCSP> ocspRef : ocspRefs) {
			EncapsulatedRevocationTokenIdentifier<OCSP> token = currentOCSPSource.findBinaryForReference(ocspRef);
			if (token == null) {
				token = listOCSPSource.findBinaryForReference(ocspRef);
			}
			if (token != null) {
				addReferences(timestampedReferences, createReferencesForOCSPBinary((OCSPResponseBinary) token, listCertificateSource));
			} else {
				addReference(timestampedReferences, new TimestampedReference(ocspRef.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
			}
		}
		return timestampedReferences;
	}

	/**
	 * Enriches embedded time-stamp tokens with evidence record references
	 *
	 * @param evidenceRecord {@link EvidenceRecord}
	 */
	protected void processEvidenceRecordTimestamps(EvidenceRecord evidenceRecord) {
		for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
			ensureOnlyDataTimestampReferencesPresent(timestampToken.getTimestampedReferences(), evidenceRecord.getTimestampedReferences());
			addReferences(timestampToken.getTimestampedReferences(), evidenceRecord.getTimestampedReferences());
		}
	}

	/**
	 * Enriches embedded evidence records with the covered references
	 *
	 * @param evidenceRecord {@link EvidenceRecord}
	 */
	protected void processEmbeddedEvidenceRecords(EvidenceRecord evidenceRecord) {
		for (EvidenceRecord embeddedEvidenceRecord : evidenceRecord.getDetachedEvidenceRecords()) {
			addReferences(embeddedEvidenceRecord.getTimestampedReferences(), evidenceRecord.getTimestampedReferences());
			processEvidenceRecordTimestamps(embeddedEvidenceRecord);
		}
	}

	/**
	 * This method is a workaround to ensure time-stamps from evidence record do not refer
	 * signature or time-stamp files in addition to token references
	 *
	 * @param referenceList a list of {@link TimestampedReference} from time-stamp token
	 * @param referencesToCheck a list of {@link TimestampedReference} from an evidence record
	 */
	private void ensureOnlyDataTimestampReferencesPresent(List<TimestampedReference> referenceList, List<TimestampedReference> referencesToCheck) {
		referenceList.removeIf(timestampedReference ->
				TimestampedObjectType.SIGNED_DATA.equals(timestampedReference.getCategory()) &&
						referencesToCheck.stream().noneMatch(timestampedReference::equals));
	}

}
