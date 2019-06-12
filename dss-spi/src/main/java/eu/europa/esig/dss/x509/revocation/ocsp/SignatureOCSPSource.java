package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.SignatureRevocationSource;
import eu.europa.esig.dss.x509.revocation.crl.CRLRef;

@SuppressWarnings("serial")
public abstract class SignatureOCSPSource extends OfflineOCSPSource implements SignatureRevocationSource<OCSPToken> {
	
	private Map<OCSPResponseIdentifier, OCSPToken> ocspTokenMap = new HashMap<OCSPResponseIdentifier, OCSPToken>();
	
	private final List<OCSPToken> revocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> attributeRevocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> timestampRevocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> dssDictionaryOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> vriDictionaryOCSPs = new ArrayList<OCSPToken>();
	
	private List<OCSPRef> completeRevocationRefsOCSPs = new ArrayList<OCSPRef>();
	private List<OCSPRef> attributeRevocationRefsOCSPs = new ArrayList<OCSPRef>();
	private List<OCSPRef> timestampRevocationRefsOCSPs = new ArrayList<OCSPRef>();
	
	private List<OCSPRef> orphanRevocationRefsOCSPs;
	
	/**
	 * Map that links {@link OCSPToken}s with related {@link OCSPRef}s
	 */
	private Map<OCSPToken, Set<OCSPRef>> revocationRefsMap;

	@Override
	public List<OCSPToken> getRevocationValuesTokens() {
		return revocationValuesOCSPs;
	}

	@Override
	public List<OCSPToken> getAttributeRevocationValuesTokens() {
		return attributeRevocationValuesOCSPs;
	}

	@Override
	public List<OCSPToken> getTimestampRevocationValuesTokens() {
		return timestampRevocationValuesOCSPs;
	}

	@Override
	public List<OCSPToken> getDSSDictionaryTokens() {
		return dssDictionaryOCSPs;
	}

	@Override
	public List<OCSPToken> getVRIDictionaryTokens() {
		return vriDictionaryOCSPs;
	}

	public List<OCSPRef> getCompleteRevocationRefs() {
		return completeRevocationRefsOCSPs;
	}

	public List<OCSPRef> getAttributeRevocationRefs() {
		return attributeRevocationRefsOCSPs;
	}

	public List<OCSPRef> getTimestampRevocationRefs() {
		return timestampRevocationRefsOCSPs;
	}
	
	/**
	 * Retrieves all found OCSP Tokens
	 * @return list of {@link OCSPToken}s
	 */
	public List<OCSPToken> getAllOCSPTokens() {
		List<OCSPToken> ocspTokens = new ArrayList<OCSPToken>();
		ocspTokens.addAll(getRevocationValuesTokens());
		ocspTokens.addAll(getAttributeRevocationValuesTokens());
		ocspTokens.addAll(getTimestampRevocationValuesTokens());
		ocspTokens.addAll(getDSSDictionaryTokens());
		ocspTokens.addAll(getVRIDictionaryTokens());
		return ocspTokens;
	}

	/**
	 * Retrieves all found OCSP Refs
	 * @return list of {@link OCSPRef}s
	 */
	public List<OCSPRef> getAllOCSPReferences() {
		List<OCSPRef> ocspRefs = new ArrayList<OCSPRef>();
		ocspRefs.addAll(getCompleteRevocationRefs());
		ocspRefs.addAll(getAttributeRevocationRefs());
		ocspRefs.addAll(getTimestampRevocationRefs());
		return ocspRefs;
	}
	
	public Map<OCSPResponseIdentifier, OCSPToken> getOCSPTokenMap() {
		return ocspTokenMap;
	}
	
	/**
	 * Allows to fill all OCSP missing revocation tokens from the given {@link SignatureOCSPSource}
	 * @param signatureOCSPSource {@link SignatureOCSPSource} to populate values from
	 */
	public void populateOCSPRevocationTokenLists(SignatureOCSPSource signatureOCSPSource) {
		for (Entry<OCSPResponseIdentifier, OCSPToken> entry : signatureOCSPSource.getOCSPTokenMap().entrySet()) {
			storeOCSPToken(entry);
		}
	}
	
	/**
	 * Allows to add all OCSP values from the given {@code signatureOCSPSource}
	 * @param signatureOCSPSource {@link SignatureOCSPSource}
	 */
	protected void addValuesFromInnerSource(SignatureOCSPSource signatureOCSPSource) {
		populateOCSPRevocationTokenLists(signatureOCSPSource);

		for (OCSPResponseIdentifier ocspResponse : signatureOCSPSource.getAllOCSPIdentifiers()) {
			for (RevocationOrigin origin : ocspResponse.getOrigins()) {
				addOCSPResponse(ocspResponse, origin);
			}
		}
		for (OCSPRef ocspRef : signatureOCSPSource.getAllOCSPReferences()) {
			addReference(ocspRef, ocspRef.getOrigin());
		}
	}
	
	private void storeOCSPToken(Entry<OCSPResponseIdentifier, OCSPToken> responseTokenEntry) {
		storeOCSPToken(responseTokenEntry.getKey(), responseTokenEntry.getValue());
	}

	@Override
	protected void storeOCSPToken(OCSPResponseIdentifier ocspResponse, OCSPToken ocspToken) {
		if (ocspResponses.containsKey(ocspResponse.asXmlId()) && !ocspTokenMap.containsKey(ocspResponse)) {
			ocspTokenMap.put(ocspResponse, ocspToken);
			for (RevocationOrigin origin : ocspResponse.getOrigins()) {
				switch (origin) {
					case INTERNAL_REVOCATION_VALUES:
						revocationValuesOCSPs.add(ocspToken);
						break;
					case INTERNAL_ATTRIBUTE_REVOCATION_VALUES:
						attributeRevocationValuesOCSPs.add(ocspToken);
						break;
					case INTERNAL_TIMESTAMP_REVOCATION_VALUES:
						timestampRevocationValuesOCSPs.add(ocspToken);
						break;
					case INTERNAL_DSS:
						dssDictionaryOCSPs.add(ocspToken);
						break;
					case INTERNAL_VRI:
						vriDictionaryOCSPs.add(ocspToken);
					default:
						break;
				}
			}
		}
	}
	
	protected void addReference(OCSPRef ocspRef, RevocationOrigin origin) {
		switch (origin) {
			case COMPLETE_REVOCATION_REFS:
				if (!completeRevocationRefsOCSPs.contains(ocspRef)) {
					completeRevocationRefsOCSPs.add(ocspRef);
				}
				break;
			case ATTRIBUTE_REVOCATION_REFS:
				if (!attributeRevocationRefsOCSPs.contains(ocspRef)) {
					attributeRevocationRefsOCSPs.add(ocspRef);
				}
			case TIMESTAMP_REVOCATION_REFS:
				if (!timestampRevocationRefsOCSPs.contains(ocspRef)) {
					timestampRevocationRefsOCSPs.add(ocspRef);
				}
			default:
				break;
		}
	}
	
	/**
	 * Returns a list of {@link OCSPRef}s assigned to the given {@code ocspResponse}
	 * @param ocspResponse {@link OCSPResponseIdentifier} to get references for
	 * @return list of {@link OCSPRef}s
	 */
	public List<OCSPRef> getReferencesForOCSPIdentifier(OCSPResponseIdentifier ocspResponse) {
		List<OCSPRef> relatedRefs = new ArrayList<OCSPRef>();
		for (OCSPRef ocspRef : getAllOCSPReferences()) {
			byte[] digestValue = ocspResponse.getDigestValue(ocspRef.getDigest().getAlgorithm());
			if (Arrays.equals(ocspRef.getDigest().getValue(), digestValue)) {
				relatedRefs.add(ocspRef);
			}
		}
		return relatedRefs;
	}
	
	/**
	 * Returns a contained {@link OCSPRef} with the given {@code digest}
	 * @param digest {@link Digest} to find a {@link OCSPRef} with
	 * @return {@link OCSPRef}
	 */
	public OCSPRef getOCSPRefByDigest(Digest digest) {
		for (OCSPRef ocspRef : getAllOCSPReferences()) {
			if (digest.equals(ocspRef.getDigest())) {
				return ocspRef;
			}
		}
		return null;
	}
	
	/**
	 * Returns a list of orphan CRL Refs
	 * @return list of {@link CRLRef}s
	 */
	public List<OCSPRef> getOrphanOCSPRefs() {
		if (orphanRevocationRefsOCSPs == null) {
			orphanRevocationRefsOCSPs = new ArrayList<OCSPRef>();
			for (OCSPRef ocspRef : getAllOCSPReferences()) {
				if (getIdentifier(ocspRef) == null) {
					orphanRevocationRefsOCSPs.add(ocspRef);
				}
			}
		}
		return orphanRevocationRefsOCSPs;
	}

	/**
	 * Retrieves a list of found OCSP Tokens for the given {@code revocationRefs}
	 * @param revocationRefs list of {@link OCSPRef} to get tokens for
	 * @return list of {@link OCSPToken}s
	 */
	public List<OCSPToken> findTokensFromRefs(List<OCSPRef> revocationRefs) {
		if (Utils.isMapEmpty(revocationRefsMap)) {
			collectRevocationRefsMap();
		}
		List<OCSPToken> tokensFromRefs = new ArrayList<OCSPToken>();
		for (Entry<OCSPToken, Set<OCSPRef>> revocationMapEntry : revocationRefsMap.entrySet()) {
			for (OCSPRef tokenRevocationRef : revocationMapEntry.getValue()) {
				if (revocationRefs.contains(tokenRevocationRef)) {
					tokensFromRefs.add(revocationMapEntry.getKey());
					break;
				}
			}
		}
		return tokensFromRefs;
	}
	
	/**
	 * Retrieves a set of found OCSP Refs for the given {@code revocationToken}
	 * @param revocationToken {@link OCSPToken} to get references for
	 * @return list of {@link OCSPRef}s
	 */
	public Set<OCSPRef> findRefsForRevocationToken(OCSPToken revocationToken) {
		if (Utils.isMapEmpty(revocationRefsMap)) {
			collectRevocationRefsMap();
		}
		Set<OCSPRef> revocationRefs = revocationRefsMap.get(revocationToken);
		if (revocationRefs != null) {
			return revocationRefs;
		} else {
			return Collections.emptySet();
		}
	}
	
	private void collectRevocationRefsMap() {
		revocationRefsMap = new HashMap<OCSPToken, Set<OCSPRef>>();
		for (OCSPToken revocationToken : getAllOCSPTokens()) {
			for (OCSPRef ocspRef : getAllOCSPReferences()) {
				if (ocspRef.getDigest() != null) {
					if (Arrays.equals(ocspRef.getDigest().getValue(), revocationToken.getDigest(ocspRef.getDigest().getAlgorithm()))) {
						addReferenceToMap(revocationToken, ocspRef);
					}
					
				} else if (!ocspRef.getProducedAt().equals(revocationToken.getProductionDate())) {
					// continue
				} else if (ocspRef.getResponderId().getName() != null &&
						ocspRef.getResponderId().getName().equals(revocationToken.getIssuerX500Principal().getName())) {
					addReferenceToMap(revocationToken, ocspRef);
					
				} else if (ocspRef.getResponderId().getKey() != null && Arrays.equals(ocspRef.getResponderId().getKey(), 
						DSSASN1Utils.computeSkiFromCertPublicKey(revocationToken.getPublicKeyOfTheSigner()))) {
					addReferenceToMap(revocationToken, ocspRef);
					
				}
			}
		}
	}
	
	private void addReferenceToMap(OCSPToken revocationToken, OCSPRef reference) {
		if (revocationRefsMap.containsKey(revocationToken)) {
			revocationRefsMap.get(revocationToken).add(reference);
		} else {
			revocationRefsMap.put(revocationToken, new HashSet<OCSPRef>(Arrays.asList(reference)));
		}
	}

}
