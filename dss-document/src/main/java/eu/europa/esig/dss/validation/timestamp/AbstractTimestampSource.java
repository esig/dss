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
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Contains a set of {@link TimestampToken}s found in a {@link DefaultAdvancedSignature} object
 */
@SuppressWarnings("serial")
public abstract class AbstractTimestampSource {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractTimestampSource.class);

	/**
	 * Adds {@code referenceToAdd} to {@code referenceList} without duplicates
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
	 */
	protected List<TimestampedReference> getEncapsulatedValuesFromTimestamp(TimestampToken timestampedTimestamp) {
		final List<TimestampedReference> references = new ArrayList<>();
		for (final CertificateToken certificate : timestampedTimestamp.getCertificates()) {
			addReference(references, certificate.getDSSId(), TimestampedObjectType.CERTIFICATE);
		}
		for (final CertificateRef certificateRef : timestampedTimestamp.getCertificateRefs()) {
			addReference(references, new TimestampedReference(certificateRef.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		TimestampCRLSource timestampCRLSource = timestampedTimestamp.getCRLSource();
		for (EncapsulatedRevocationTokenIdentifier<CRL> revocationBinary : timestampCRLSource.getAllRevocationBinaries()) {
			addReference(references, revocationBinary, TimestampedObjectType.REVOCATION);
		}
		for (EncapsulatedRevocationTokenIdentifier<CRL> revocationBinary : timestampCRLSource.getAllReferencedRevocationBinaries()) {
			addReference(references, revocationBinary, TimestampedObjectType.REVOCATION);
		}
		TimestampOCSPSource timestampOCSPSource = timestampedTimestamp.getOCSPSource();
		for (EncapsulatedRevocationTokenIdentifier<OCSP> revocationBinary : timestampOCSPSource.getAllRevocationBinaries()) {
			addReference(references, revocationBinary, TimestampedObjectType.REVOCATION);
		}
		for (EncapsulatedRevocationTokenIdentifier<OCSP> revocationBinary : timestampOCSPSource.getAllReferencedRevocationBinaries()) {
			addReference(references, revocationBinary, TimestampedObjectType.REVOCATION);
		}
		return references;
	}

	protected List<TimestampedReference> getEncapsulatedReferencesFromTimestamps(List<TimestampToken> timestampTokens) {
		final List<TimestampedReference> references = new ArrayList<>();
		for (TimestampToken timestampToken : timestampTokens) {
			addReferences(references, getReferencesFromTimestamp(timestampToken));
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
			addReference(references, new TimestampedReference(certificateToken.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
		}
		return references;
	}

	protected List<TimestampedReference> createReferencesForIdentifiers(
			Collection<? extends Identifier> identifiers, TimestampedObjectType timestampedObjectType) {
		List<TimestampedReference> timestampedReferences = new ArrayList<>();
		for (Identifier identifier : identifiers) {
			timestampedReferences.add(new TimestampedReference(identifier.asXmlId(), timestampedObjectType));
		}
		return timestampedReferences;
	}

}
