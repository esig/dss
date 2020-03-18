package eu.europa.esig.dss.spi.x509.revocation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.identifier.MultipleDigestIdentifier;
import eu.europa.esig.dss.utils.Utils;

public class RevocationContainer<R extends Revocation> {

	private final Map<MultipleDigestIdentifier, List<RevocationOrigin>> binaryOrigins = new HashMap<>();

	private final Map<RevocationToken<R>, List<RevocationOrigin>> tokenOrigins = new HashMap<>();

	private final Map<RevocationRef<R>, List<RevocationRefOrigin>> referenceOrigins = new HashMap<>();

	private final RevocationTokenRefMatcher<R> tokenRefMatcher;

	public RevocationContainer(RevocationTokenRefMatcher<R> tokenRefMatcher) {
		Objects.requireNonNull(tokenRefMatcher);
		this.tokenRefMatcher = tokenRefMatcher;
	}

	/**
	 * This method adds a token binary with its origin
	 * 
	 * @param binary the binary token to be added
	 * @param origin the origin where the token has been found
	 */
	public void addBinary(MultipleDigestIdentifier binary, RevocationOrigin origin) {
		Objects.requireNonNull(binary, "The binary is null");
		Objects.requireNonNull(origin, "The origin is null");
		List<RevocationOrigin> origins = binaryOrigins.get(binary);
		if (origins == null) {
			origins = new ArrayList<>();
			binaryOrigins.put(binary, origins);
		}
		origins.add(origin);
	}

	/**
	 * This method returns the collected binaries
	 * 
	 * @return a Set of all collected binaries
	 */
	public Set<MultipleDigestIdentifier> getCollectedBinaries() {
		return binaryOrigins.keySet();
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
		List<RevocationOrigin> origins = tokenOrigins.get(token);
		if (origins == null) {
			origins = new ArrayList<>();
			tokenOrigins.put(token, origins);
		}
		origins.add(origin);
	}

	/**
	 * This method adds a {@code RevocationToken} from the binary
	 * 
	 * @param token the token to be added
	 * @param binary the binary where the token has been extracted
	 */
	public void addRevocation(RevocationToken<R> token, MultipleDigestIdentifier binary) {
		Objects.requireNonNull(token, "The token is null");
		Objects.requireNonNull(binary, "The origin is null");
		List<RevocationOrigin> origins = binaryOrigins.get(binary);
		if (origins == null) {
			throw new IllegalStateException(String.format("Unable to find the binary '{}'", binary.asXmlId()));
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
		List<RevocationRefOrigin> origins = referenceOrigins.get(reference);
		if (origins == null) {
			origins = new ArrayList<>();
			referenceOrigins.put(reference, origins);
		}
		origins.add(origin);
	}

	/**
	 * Retrieves a Set of all found {@code RevocationToken}
	 * 
	 * @return all {@code RevocationToken}
	 */
	public Set<RevocationToken<R>> getAllRevocationTokens() {
		return tokenOrigins.keySet();
	}

	/**
	 * Retrieves a Set of all found {@code RevocationRef}
	 * 
	 * @return all {@code RevocationRef}
	 */
	public Set<RevocationRef<R>> getAllRevocationReferences() {
		return referenceOrigins.keySet();
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in the CMS
	 * SignedData
	 * 
	 * NOTE: Applicable only for CAdES revocation sources
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getCMSSignedDataRevocationTokens() {
		return getTokensByOrigin(RevocationOrigin.CMS_SIGNED_DATA);
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'RevocationValues' element
	 * 
	 * NOTE: Applicable only for CAdES and XAdES revocation sources
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getRevocationValuesTokens() {
		return getTokensByOrigin(RevocationOrigin.REVOCATION_VALUES);
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'AttributeRevocationValues' element
	 * 
	 * NOTE: Applicable only for XAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getAttributeRevocationValuesTokens() {
		return getTokensByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in
	 * 'TimestampValidationData' element
	 * 
	 * NOTE: Applicable only for XAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getTimestampValidationDataTokens() {
		return getTokensByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'DSS'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getDSSDictionaryTokens() {
		return getTokensByOrigin(RevocationOrigin.DSS_DICTIONARY);
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in 'VRI'
	 * dictionary
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getVRIDictionaryTokens() {
		return getTokensByOrigin(RevocationOrigin.VRI_DICTIONARY);
	}

	/**
	 * Retrieves the list of all {@link RevocationToken}s present in the ADBE
	 * element
	 * 
	 * NOTE: Applicable only for PAdES revocation source
	 * 
	 * @return list of {@link RevocationToken}s
	 */
	public List<RevocationToken<R>> getADBERevocationValuesTokens() {
		return getTokensByOrigin(RevocationOrigin.ADBE_REVOCATION_INFO_ARCHIVAL);
	}

	/**
	 * Retrieves the list of all {@link RevocationRef}s present in the signature
	 * 'complete-revocation-references' attribute (used in CAdES and XAdES)
	 * 
	 * @return list of {@link RevocationRef}s
	 */
	public List<RevocationRef<R>> getCompleteRevocationRefs() {
		return getReferencesByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
	}

	/**
	 * Retrieves the list of all {@link RevocationRef}s present in the signature
	 * 'attribute-revocation-references' attribute (used in CAdES and XAdES)
	 * 
	 * @return list of {@link RevocationRef}s
	 */
	public List<RevocationRef<R>> getAttributeRevocationRefs() {
		return getReferencesByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	/**
	 * Retrieves a List of found {@code RevocationRef} for the given
	 * {@code RevocationToken}
	 * 
	 * @param revocationToken {@link RevocationToken} to get references for
	 * @return List of {@link RevocationRef}s
	 */
	public List<RevocationRef<R>> findRefsForRevocationToken(RevocationToken<R> revocationToken) {
		List<RevocationRef<R>> result = new ArrayList<>();
		for (Entry<RevocationRef<R>, List<RevocationRefOrigin>> entry : referenceOrigins.entrySet()) {
			RevocationRef<R> currentReference = entry.getKey();
			if (tokenRefMatcher.match(revocationToken, currentReference)) {
				result.add(currentReference);
			}
		}
		return result;
	}

	/**
	 * This method verifies if a given {@code RevocationRef} is an orphan (not
	 * linked to a complete {@code RevocationToken)
	 * 
	 * @param reference the reference to be tested
	 * 
	 * @return true if the given reference is an orphan
	 */
	public boolean isOrphan(RevocationRef<R> reference) {
		for (RevocationToken<R> token : tokenOrigins.keySet()) {
			if (tokenRefMatcher.match(token, reference)) {
				return false;
			}
		}
		return true;
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
		for (Entry<RevocationToken<R>, List<RevocationOrigin>> entry : tokenOrigins.entrySet()) {
			List<RevocationOrigin> currentOrigins = entry.getValue();
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
		for (Entry<RevocationRef<R>, List<RevocationRefOrigin>> entry : referenceOrigins.entrySet()) {
			List<RevocationRefOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

}
