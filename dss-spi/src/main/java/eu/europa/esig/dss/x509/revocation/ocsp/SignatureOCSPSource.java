package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.Digest;
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
	
	public List<OCSPRef> getAllOCSPReferences() {
		List<OCSPRef> ocspRefs = new ArrayList<OCSPRef>();
		ocspRefs.addAll(getCompleteRevocationRefs());
		ocspRefs.addAll(getAttributeRevocationRefs());
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
			addReference(ocspRef, ocspRef.getLocation());
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
			byte[] digestValue = ocspResponse.getDigestValue(ocspRef.getDigestAlgorithm());
			if (Arrays.equals(ocspRef.getDigestValue(), digestValue)) {
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
			if (digest.getAlgorithm().equals(ocspRef.getDigestAlgorithm()) && Arrays.equals(digest.getValue(), ocspRef.getDigestValue())) {
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

}
