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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

/**
 * Represents a revocation sources for a data obtained from an offline source (e.g. signature)
 *
 * @param <R> the revocation class type (CRL/OCSP)
 */
public abstract class OfflineRevocationSource<R extends Revocation> implements RevocationSource<R>, MultipleRevocationSource<R> {

	private static final long serialVersionUID = 8270762277613989997L;

	/** The map between revocation token identifiers and corresponding origins */
	private final Map<EncapsulatedRevocationTokenIdentifier<R>, Set<RevocationOrigin>> binaryOrigins = new HashMap<>();

	/** A map between computed {@code RevocationToken}s and their origins */
	private final Map<RevocationToken<R>, Set<RevocationOrigin>> tokenOrigins = new HashMap<>();

	/** A map between revocation references and their origins */
	private final Map<RevocationRef<R>, Set<RevocationRefOrigin>> referenceOrigins = new HashMap<>();

	/** The use RevocationTokenRefMatcher */
	private final RevocationTokenRefMatcher<R> tokenRefMatcher;

	/**
	 * The default constructor
	 *
	 * @param tokenRefMatcher {@link RevocationTokenRefMatcher} used to match tokens and their corresponding references
	 */
	protected OfflineRevocationSource(RevocationTokenRefMatcher<R> tokenRefMatcher) {
		Objects.requireNonNull(tokenRefMatcher);
		this.tokenRefMatcher = tokenRefMatcher;
	}

	/**
	 * This method adds a token binary with its origin
	 * 
	 * @param binary the binary token to be added
	 * @param origin the origin where the token has been found
	 */
	public void addBinary(EncapsulatedRevocationTokenIdentifier<R> binary, RevocationOrigin origin) {
		Objects.requireNonNull(binary, "The binary is null");
		Objects.requireNonNull(origin, "The origin is null");
		binaryOrigins.computeIfAbsent(binary, k -> new HashSet<>()).add(origin);
	}

	/**
	 * This method adds a revocation token with its origin
	 * 
	 * @param token  the revocation token to be added
	 * @param origin the origin where the token has been found
	 */
	public void addRevocation(RevocationToken<R> token, RevocationOrigin origin) {
		Objects.requireNonNull(token, "The token is null");
		Objects.requireNonNull(origin, "The origin is null");
		tokenOrigins.computeIfAbsent(token, k -> new HashSet<>()).add(origin);
	}

	/**
	 * This method adds a {@code RevocationToken} from the binary
	 * 
	 * @param token the token to be added
	 * @param binary the binary where the token has been extracted
	 */
	public void addRevocation(RevocationToken<R> token, EncapsulatedRevocationTokenIdentifier<R> binary) {
		Objects.requireNonNull(token, "The token is null");
		
		Objects.requireNonNull(binary, "The origin is null");
		Set<RevocationOrigin> origins = getAllRevocationBinariesWithOrigins().get(binary);
		if (origins == null) {
			throw new IllegalStateException(String.format("Unable to find the binary '%s'", binary.asXmlId()));
		}
		for (RevocationOrigin origin : origins) {
			addRevocation(token, origin);
		}
	}

	/**
	 * This method adds a revocation reference with its origin
	 * 
	 * @param reference the revocation reference to be added
	 * @param origin    the origin where the reference has been found
	 */
	public void addRevocationReference(RevocationRef<R> reference, RevocationRefOrigin origin) {
		Objects.requireNonNull(reference, "The reference is null");
		Objects.requireNonNull(origin, "The origin is null");
		referenceOrigins.computeIfAbsent(reference, k -> new HashSet<>()).add(origin);
	}

	/**
	 * Retrieves all found revocation binaries
	 * 
	 * @return a Set of {@code EncapsulatedRevocationTokenIdentifier}
	 */
	public Set<EncapsulatedRevocationTokenIdentifier<R>> getAllRevocationBinaries() {
		return getAllRevocationBinariesWithOrigins().keySet();
	}

	/**
	 * Retrieves all found revocation binaries with their origins
	 * 
	 * @return a Map of {@code EncapsulatedRevocationTokenIdentifier} with their
	 *         origins
	 */
	public Map<EncapsulatedRevocationTokenIdentifier<R>, Set<RevocationOrigin>> getAllRevocationBinariesWithOrigins() {
		return binaryOrigins;
	}

	/**
	 * Retrieves a Set of all found {@code RevocationToken}
	 * 
	 * @return all {@code RevocationToken}
	 */
	public Set<RevocationToken<R>> getAllRevocationTokens() {
		return getAllRevocationTokensWithOrigins().keySet();
	}

	/**
	 * Returns all tokens with their origins
	 * 
	 * @return a map of tokens with the different origins
	 */
	public Map<RevocationToken<R>, Set<RevocationOrigin>> getAllRevocationTokensWithOrigins() {
		return tokenOrigins;
	}

	/**
	 * Returns a Map of unique {@code RevocationToken} based on binary (a same
	 * binary can cover several certificates) with their origins
	 * 
	 * @return a map of tokens with the different origins
	 */
	public Map<RevocationToken<R>, Set<RevocationOrigin>> getUniqueRevocationTokensWithOrigins() {
		Map<RevocationToken<R>, Set<RevocationOrigin>> result = new HashMap<>();
		List<TokenIdentifier> knownIds = new ArrayList<>();
		for (Entry<RevocationToken<R>, Set<RevocationOrigin>> entry : getAllRevocationTokensWithOrigins().entrySet()) {
			TokenIdentifier currentId = entry.getKey().getDSSId();
			if (!knownIds.contains(currentId)) {
				result.put(entry.getKey(), entry.getValue());
				knownIds.add(currentId);
			}
		}
		return result;
	}

	/**
	 * Retrieves a Set of all found {@code RevocationRef}
	 * 
	 * @return all {@code RevocationRef}
	 */
	public Set<RevocationRef<R>> getAllRevocationReferences() {
		return getRevocationReferencesWithOrigins().keySet();
	}

	/**
	 * Returns a map of revocation references with the corresponding origins
	 *
	 * @return a map between {@link RevocationRef}s and a set of {@link RevocationRefOrigin}s
	 */
	protected Map<RevocationRef<R>, Set<RevocationRefOrigin>> getRevocationReferencesWithOrigins() {
		return referenceOrigins;
	}

	/**
	 * This method returns the latest issued revocation token from a set of all revocation data found for
	 * the given {@code certificateToken}.
	 * Returns NULL, if no corresponding revocation data found for the certificate.
	 *
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerCertificateToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return {@link RevocationToken}
	 */
	@Override
	public RevocationToken<R> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		RevocationToken<R> latestRevocationToken = null;

		final List<RevocationToken<R>> revocationTokens = getRevocationTokens(certificateToken, issuerCertificateToken);
		if (Utils.isCollectionNotEmpty(revocationTokens)) {
			for (RevocationToken<R> revocationToken : revocationTokens) {
				if (latestRevocationToken == null || (revocationToken.getProductionDate() != null
						&& latestRevocationToken.getProductionDate().before(revocationToken.getProductionDate()))) {
					latestRevocationToken = revocationToken;
				}
			}
		}

		return latestRevocationToken;
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in the CMS SignedData
	 * 
	 * NOTE: Applicable only for CAdES revocation sources
	 * 
	 * @return list of {@code EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getCMSSignedDataRevocationBinaries() {
		return getBinariesByOrigin(RevocationOrigin.CMS_SIGNED_DATA);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in the CMS
	 * SignedData
	 * 
	 * NOTE: Applicable only for CAdES revocation sources
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getCMSSignedDataRevocationTokens() {
		return getTokensByOrigin(RevocationOrigin.CMS_SIGNED_DATA);
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in 'RevocationValues' element
	 *
	 * @return list of {@code EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getRevocationValuesBinaries() {
		return getBinariesByOrigin(RevocationOrigin.REVOCATION_VALUES);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in
	 * 'RevocationValues' element
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getRevocationValuesTokens() {
		return getTokensByOrigin(RevocationOrigin.REVOCATION_VALUES);
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in 'AttributeRevocationValues' element
	 *
	 * @return list of {@code EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getAttributeRevocationValuesBinaries() {
		return getBinariesByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in
	 * 'AttributeRevocationValues' element
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getAttributeRevocationValuesTokens() {
		return getTokensByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in 'TimestampValidationData' element
	 *
	 * @return list of {@code EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getTimestampValidationDataBinaries() {
		return getBinariesByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in
	 * 'TimestampValidationData' element
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getTimestampValidationDataTokens() {
		return getTokensByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in 'DSS' dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getDSSDictionaryBinaries() {
		return getBinariesByOrigin(RevocationOrigin.DSS_DICTIONARY);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'DSS'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getDSSDictionaryTokens() {
		return getTokensByOrigin(RevocationOrigin.DSS_DICTIONARY);
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in 'VRI' dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getVRIDictionaryBinaries() {
		return getBinariesByOrigin(RevocationOrigin.VRI_DICTIONARY);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in 'VRI'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getVRIDictionaryTokens() {
		return getTokensByOrigin(RevocationOrigin.VRI_DICTIONARY);
	}

	/**
	 * Retrieves the list of all {@code EncapsulatedRevocationTokenIdentifier}s
	 * present in the ADBE signed attribute
	 *
	 * @return list of {@code EncapsulatedRevocationTokenIdentifier}s
	 */
	public List<EncapsulatedRevocationTokenIdentifier<R>> getADBERevocationValuesBinaries() {
		return getBinariesByOrigin(RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
	}

	/**
	 * Retrieves the list of all {@code RevocationToken}s present in
	 * the ADBE signed attribute
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@code RevocationToken}s
	 */
	public List<RevocationToken<R>> getADBERevocationValuesTokens() {
		return getTokensByOrigin(RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
	}

	/**
	 * Retrieves the list of all {@code RevocationRef}s present in the signature
	 * 'complete-revocation-references' attribute (used in CAdES and XAdES)
	 * 
	 * @return list of {@code RevocationRef}s
	 */
	public List<RevocationRef<R>> getCompleteRevocationRefs() {
		return getReferencesByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
	}

	/**
	 * Retrieves the list of all {@code RevocationRef}s present in the signature
	 * 'attribute-revocation-references' attribute (used in CAdES and XAdES)
	 * 
	 * @return list of {@code RevocationRef}s
	 */
	public List<RevocationRef<R>> getAttributeRevocationRefs() {
		return getReferencesByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	/**
	 * Retrieves a Map of found {@code RevocationRef} with their origins for the
	 * given {@code RevocationToken}
	 * 
	 * @param revocationToken {@code RevocationToken} to get references for
	 * @return Map of {@code RevocationRef}s with their origins
	 */
	public Map<RevocationRef<R>, Set<RevocationRefOrigin>> findRefsAndOriginsForRevocationToken(RevocationToken<R> revocationToken) {
		Map<RevocationRef<R>, Set<RevocationRefOrigin>> result = new HashMap<>();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : getRevocationReferencesWithOrigins().entrySet()) {
			RevocationRef<R> currentReference = entry.getKey();
			if (tokenRefMatcher.match(revocationToken, currentReference)) {
				result.put(entry.getKey(), entry.getValue());
			}
		}
		return result;
	}

	/**
	 * Retrieves a Map of orphan {@code RevocationRef} with their
	 * {@code RevocationRefOrigin}s for a given
	 * {@code EncapsulatedRevocationTokenIdentifier}
	 *
	 * @param identifier {@link EncapsulatedRevocationTokenIdentifier}
	 * @return a Map of orphan references with their origins
	 */
	public Map<RevocationRef<R>, Set<RevocationRefOrigin>> findRefsAndOriginsForBinary(
			EncapsulatedRevocationTokenIdentifier<R> identifier) {
		Map<RevocationRef<R>, Set<RevocationRefOrigin>> result = new HashMap<>();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : getRevocationReferencesWithOrigins().entrySet()) {
			RevocationRef<R> currentReference = entry.getKey();
			if (tokenRefMatcher.match(identifier, currentReference)) {
				result.put(currentReference, entry.getValue());
			}
		}
		return result;
	}

	/**
	 * Returns the linked {@code EncapsulatedRevocationTokenIdentifier} for a given
	 * {@code RevocationRef}
	 * 
	 * @param ref the {@code RevocationRef} to find
	 * @return the related {@code EncapsulatedRevocationTokenIdentifier}
	 */
	public EncapsulatedRevocationTokenIdentifier<R> findBinaryForReference(RevocationRef<R> ref) {
		for (EncapsulatedRevocationTokenIdentifier<R> binary : getAllRevocationBinariesWithOrigins().keySet()) {
			if (tokenRefMatcher.match(binary, ref)) {
				return binary;
			}
		}
		return null;
	}

	/**
	 * Retrieves a Map of orphan {@code RevocationRef} with their
	 * {@code RevocationRefOrigin}s
	 * 
	 * @return a Map of orphan references with their origins
	 */
	public Map<RevocationRef<R>, Set<RevocationRefOrigin>> getOrphanRevocationReferencesWithOrigins() {
		Map<RevocationRef<R>, Set<RevocationRefOrigin>> result = new HashMap<>();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : getRevocationReferencesWithOrigins().entrySet()) {
			RevocationRef<R> ref = entry.getKey();
			if (isOrphan(ref)) {
				result.put(ref, entry.getValue());
			}
		}
		return result;
	}

	/**
	 * This method verifies if a given {@code RevocationRef} is an orphan (not
	 * linked to a complete {@code RevocationToken}
	 * 
	 * @param reference the reference to be tested
	 * 
	 * @return true if the given reference is an orphan
	 */
	public boolean isOrphan(RevocationRef<R> reference) {
		for (RevocationToken<R> token : getAllRevocationTokensWithOrigins().keySet()) {
			if (tokenRefMatcher.match(token, reference)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Retrieves the Set of tokens which have a reference
	 * 
	 * @return a Set of Token Identifiers which are referenced
	 */
	public Set<EncapsulatedRevocationTokenIdentifier<R>> getAllReferencedRevocationBinaries() {
		Set<EncapsulatedRevocationTokenIdentifier<R>> result = new HashSet<>();
		for (RevocationRef<R> reference : getRevocationReferencesWithOrigins().keySet()) {
			for (EncapsulatedRevocationTokenIdentifier<R> identifier : getAllRevocationBinariesWithOrigins().keySet()) {
				if (tokenRefMatcher.match(identifier, reference)) {
					result.add(identifier);
				}
			}
		}
		return result;
	}

	/**
	 * This method checks if the revocation source is empty
	 * 
	 * @return true if the source is empty
	 */
	public boolean isEmpty() {
		return Utils.isMapEmpty(getAllRevocationBinariesWithOrigins())
				&& Utils.isMapEmpty(getAllRevocationTokensWithOrigins())
				&& Utils.isMapEmpty(getRevocationReferencesWithOrigins());
	}

	/**
	 * Retrieves a List of {@code EncapsulatedRevocationTokenIdentifier} for a given
	 * {@code RevocationOrigin}
	 * 
	 * @param origin the origin to find
	 * 
	 * @return a list of {@code EncapsulatedRevocationTokenIdentifier}
	 */
	private List<EncapsulatedRevocationTokenIdentifier<R>> getBinariesByOrigin(RevocationOrigin origin) {
		List<EncapsulatedRevocationTokenIdentifier<R>> result = new ArrayList<>();
		for (Entry<EncapsulatedRevocationTokenIdentifier<R>, Set<RevocationOrigin>> entry : getAllRevocationBinariesWithOrigins().entrySet()) {
			Set<RevocationOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

	/**
	 * Retrieves a List of {@code RevocationToken} for a given
	 * {@code RevocationOrigin}
	 * 
	 * @param origin the origin to find
	 * 
	 * @return a list of {@code RevocationToken}
	 */
	private List<RevocationToken<R>> getTokensByOrigin(RevocationOrigin origin) {
		List<RevocationToken<R>> result = new ArrayList<>();
		for (Entry<RevocationToken<R>, Set<RevocationOrigin>> entry : getAllRevocationTokensWithOrigins().entrySet()) {
			Set<RevocationOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

	/**
	 * Retrieves a List of {@code RevocationRef} for a given
	 * {@code RevocationRefOrigin}
	 * 
	 * @param origin the origin to find
	 * 
	 * @return a list of {@code RevocationRef}
	 */
	private List<RevocationRef<R>> getReferencesByOrigin(RevocationRefOrigin origin) {
		List<RevocationRef<R>> result = new ArrayList<>();
		for (Entry<RevocationRef<R>, Set<RevocationRefOrigin>> entry : getRevocationReferencesWithOrigins().entrySet()) {
			Set<RevocationRefOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

}
