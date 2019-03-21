package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.esig.dss.x509.revocation.SignatureRevocationSource;

@SuppressWarnings("serial")
public abstract class SignatureOCSPSource extends OfflineOCSPSource implements SignatureRevocationSource<OCSPToken> {
	
	private Map<BasicOCSPResp, OCSPToken> ocspTokenMap = new HashMap<BasicOCSPResp, OCSPToken>();
	
	private final List<OCSPToken> revocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> attributeRevocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> timestampRevocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> dssDictionaryOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> vriDictionaryOCSPs = new ArrayList<OCSPToken>();

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
	
	public Map<BasicOCSPResp, OCSPToken> getOCSPTokenMap() {
		return ocspTokenMap;
	}
	
	/**
	 * Allows to fill all OCSP missing revocation tokens from the given {@link SignatureOCSPSource}
	 * @param signatureOCSPSource {@link SignatureOCSPSource} to populate values from
	 */
	public void populateOCSPRevocationTokenLists(SignatureOCSPSource signatureOCSPSource) {
		Map<BasicOCSPResp, OCSPToken> mapToPopulateFrom = signatureOCSPSource.getOCSPTokenMap();
		for (Entry<BasicOCSPResp, OCSPToken> entry : mapToPopulateFrom.entrySet()) {
			storeOCSPToken(entry);
		}
	}
	
	private void storeOCSPToken(Entry<BasicOCSPResp, OCSPToken> responseTokenEntry) {
		storeOCSPToken(responseTokenEntry.getKey(), responseTokenEntry.getValue());
	}

	@Override
	protected void storeOCSPToken(BasicOCSPResp basicOCSPResp, OCSPToken ocspToken) {
		if (ocspResponses.containsKey(basicOCSPResp) && !ocspTokenMap.containsKey(basicOCSPResp)) {
			ocspTokenMap.put(basicOCSPResp, ocspToken);
			switch (ocspToken.getOrigin()) {
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
