package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.SignatureRevocationSource;

@SuppressWarnings("serial")
public abstract class SignatureOCSPSource extends OfflineOCSPSource implements SignatureRevocationSource<OCSPToken> {
	
	private Map<OCSPResponse, OCSPToken> ocspTokenMap = new HashMap<OCSPResponse, OCSPToken>();
	
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
	
	public Map<OCSPResponse, OCSPToken> getOCSPTokenMap() {
		return ocspTokenMap;
	}
	
	/**
	 * Allows to fill all OCSP missing revocation tokens from the given {@link SignatureOCSPSource}
	 * @param signatureOCSPSource {@link SignatureOCSPSource} to populate values from
	 */
	public void populateOCSPRevocationTokenLists(SignatureOCSPSource signatureOCSPSource) {
		Map<OCSPResponse, OCSPToken> mapToPopulateFrom = signatureOCSPSource.getOCSPTokenMap();
		for (Entry<OCSPResponse, OCSPToken> entry : mapToPopulateFrom.entrySet()) {
			storeOCSPToken(entry);
		}
	}
	
	private void storeOCSPToken(Entry<OCSPResponse, OCSPToken> responseTokenEntry) {
		storeOCSPToken(responseTokenEntry.getKey(), responseTokenEntry.getValue());
	}

	@Override
	protected void storeOCSPToken(OCSPResponse ocspResponse, OCSPToken ocspToken) {
		if (ocspResponses.contains(ocspResponse) && !ocspTokenMap.containsKey(ocspResponse)) {
			ocspTokenMap.put(ocspResponse, ocspToken);
			switch (ocspResponse.getOrigin()) {
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

}
