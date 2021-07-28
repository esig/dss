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
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Contains a set of {@link TimestampToken}s found in a {@link DefaultAdvancedSignature} object
 */
@SuppressWarnings("serial")
public abstract class AbstractTimestampSource {

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
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getReferencesFromTimestamp(TimestampToken timestampToken) {
		List<TimestampedReference> references = new ArrayList<>();
		addReference(references, new TimestampedReference(timestampToken.getDSSIdAsString(), TimestampedObjectType.TIMESTAMP));
		addReferences(references, timestampToken.getTimestampedReferences());
		addReferences(references, getEncapsulatedValuesFromTimestamp(timestampToken));
		return references;
	}

	/**
	 * Gets a list of all validation data embedded to the {@code timestampedTimestamp}
	 *
	 * @param timestampedTimestamp {@link TimestampToken} to extract embedded values from
	 * @return list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> getEncapsulatedValuesFromTimestamp(TimestampToken timestampedTimestamp) {
		final List<TimestampedReference> references = new ArrayList<>();

		final TimestampCertificateSource timestampCertificateSource = timestampedTimestamp.getCertificateSource();
		addReferences(references, createReferencesForCertificates(timestampCertificateSource.getCertificates()));
		addReferences(references, createReferencesForCertificateRefs(timestampCertificateSource.getAllCertificateRefs()));

		final TimestampCRLSource timestampCRLSource = timestampedTimestamp.getCRLSource();
		addReferences(references, createReferencesForCRLBinaries(timestampCRLSource.getAllRevocationBinaries()));
		addReferences(references, createReferencesForRevocationRefs(timestampCRLSource.getAllRevocationReferences()));

		final TimestampOCSPSource timestampOCSPSource = timestampedTimestamp.getOCSPSource();
		addReferences(references, createReferencesForOCSPBinaries(timestampOCSPSource.getAllRevocationBinaries()));
		addReferences(references, createReferencesForRevocationRefs(timestampOCSPSource.getAllRevocationReferences()));

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
	 * @return a list of link {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForOCSPBinaries(
			Collection<? extends EncapsulatedRevocationTokenIdentifier<OCSP>> ocspBinaryIdentifiers) {
		final List<TimestampedReference> references = new ArrayList<>();
		for (EncapsulatedRevocationTokenIdentifier<OCSP> ocspIdentifier : ocspBinaryIdentifiers) {
			if (ocspIdentifier instanceof OCSPResponseBinary) {
				OCSPResponseBinary ocspResponseBinary = (OCSPResponseBinary) ocspIdentifier;
				addReference(references, createReferenceForIdentifier(ocspResponseBinary, TimestampedObjectType.REVOCATION));

				final OCSPCertificateSource ocspCertificateSource = new OCSPCertificateSource(ocspResponseBinary.getBasicOCSPResp());
				addReferences(references, createReferencesForCertificates(ocspCertificateSource.getCertificates()));
				addReferences(references, createReferencesForCertificateRefs(ocspCertificateSource.getAllCertificateRefs()));
			}
		}
		return references;
	}

	/**
	 * Returns a list of timestamped references from the given collection of {@code certificateRefs}
	 *
	 * @param certificateRefs       a collection of {@link CertificateRef}s to get timestamped references from
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForCertificateRefs(Collection<CertificateRef> certificateRefs) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (CertificateRef certRef : certificateRefs) {
			timestampedReferences.add(new TimestampedReference(certRef.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		return timestampedReferences;
	}

	/**
	 * Returns a list of timestamped references from the given collection of {@code revocationRefs}
	 *
	 * @param revocationRefs a collection of {@link RevocationRef}s to get timestamped references from
	 * @return a list of {@link TimestampedReference}s
	 */
	protected List<TimestampedReference> createReferencesForRevocationRefs(Collection<? extends RevocationRef<?>> revocationRefs) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (RevocationRef<?> revocationRef : revocationRefs) {
			timestampedReferences.add(createReferenceForRevocationRef(revocationRef));
		}
		return timestampedReferences;
	}

	private TimestampedReference createReferenceForRevocationRef(RevocationRef<?> revocationRef) {
		return new TimestampedReference(revocationRef.getDSSIdAsString(), TimestampedObjectType.REVOCATION);
	}

}
