package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.SignatureRevocationSource;

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
		Map<OCSPResponseIdentifier, OCSPToken> mapToPopulateFrom = signatureOCSPSource.getOCSPTokenMap();
		for (Entry<OCSPResponseIdentifier, OCSPToken> entry : mapToPopulateFrom.entrySet()) {
			storeOCSPToken(entry);
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

}
