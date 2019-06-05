package eu.europa.esig.dss.x509.revocation.crl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.SignatureRevocationSource;

@SuppressWarnings("serial")
public abstract class SignatureCRLSource extends OfflineCRLSource implements SignatureRevocationSource<CRLToken> {
	
	Map<CRLBinaryIdentifier, List<CRLToken>> crlTokenMap = new HashMap<CRLBinaryIdentifier, List<CRLToken>>();
	
	private List<CRLToken> revocationValuesCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> attributeRevocationValuesCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> timestampRevocationValuesCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> dssDictionaryCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> vriDictionaryCRLs = new ArrayList<CRLToken>();
	
	private List<CRLRef> completeRevocationRefsCRLs = new ArrayList<CRLRef>();
	private List<CRLRef> attributeRevocationRefsCRLs = new ArrayList<CRLRef>();
	private List<CRLRef> timestampRevocationRefsCRLs = new ArrayList<CRLRef>();
	
	private List<CRLRef> orphanRevocationRefsCRLs;
	
	/**
	 * Map that links {@link CRLToken}s with related {@link CRLRef}s
	 */
	private Map<CRLToken, Set<CRLRef>> revocationRefsMap;

	@Override
	public List<CRLToken> getRevocationValuesTokens() {
		return revocationValuesCRLs;
	}

	@Override
	public List<CRLToken> getAttributeRevocationValuesTokens() {
		return attributeRevocationValuesCRLs;
	}

	@Override
	public List<CRLToken> getTimestampRevocationValuesTokens() {
		return timestampRevocationValuesCRLs;
	}

	@Override
	public List<CRLToken> getDSSDictionaryTokens() {
		return dssDictionaryCRLs;
	}

	@Override
	public List<CRLToken> getVRIDictionaryTokens() {
		return vriDictionaryCRLs;
	}

	public List<CRLRef> getCompleteRevocationRefs() {
		return completeRevocationRefsCRLs;
	}

	public List<CRLRef> getAttributeRevocationRefs() {
		return attributeRevocationRefsCRLs;
	}

	public List<CRLRef> getTimestampRevocationRefs() {
		return timestampRevocationRefsCRLs;
	}
	
	/**
	 * Retrieves all found CRL Tokens
	 * @return list of {@link CRLToken}s
	 */
	public List<CRLToken> getAllCRLTokens() {
		List<CRLToken> crlTokens = new ArrayList<CRLToken>();
		crlTokens.addAll(getRevocationValuesTokens());
		crlTokens.addAll(getAttributeRevocationValuesTokens());
		crlTokens.addAll(getTimestampRevocationValuesTokens());
		crlTokens.addAll(getDSSDictionaryTokens());
		crlTokens.addAll(getVRIDictionaryTokens());
		return crlTokens;
	}

	/**
	 * Retrieves all found CRL Refs
	 * @return list of {@link CRLRef}s
	 */
	public List<CRLRef> getAllCRLReferences() {
		List<CRLRef> crlRefs = new ArrayList<CRLRef>();
		crlRefs.addAll(getCompleteRevocationRefs());
		crlRefs.addAll(getAttributeRevocationRefs());
		crlRefs.addAll(getTimestampRevocationRefs());
		return crlRefs;
	}
	
	public Map<CRLBinaryIdentifier, List<CRLToken>> getCRLTokenMap() {
		return crlTokenMap;
	}
	
	/**
	 * Allows to fill all CRL missing revocation values from the given {@code signatureCRLSource}
	 * @param signatureCRLSource {@link SignatureCRLSource} to populate values from
	 */
	public void populateCRLRevocationValues(SignatureCRLSource signatureCRLSource) {
		for (Entry<CRLBinaryIdentifier, List<CRLToken>> entry : signatureCRLSource.getCRLTokenMap().entrySet()) {
			for (CRLToken crlToken : entry.getValue()) {
				storeCRLToken(entry.getKey(), crlToken);
			}
		}
	}
	
	/**
	 * Allows to add all CRL values from the given {@code signatureCRLSource}
	 * @param signatureCRLSource {@link SignatureCRLSource}
	 */
	protected void addValuesFromInnerSource(SignatureCRLSource signatureCRLSource) {
		populateCRLRevocationValues(signatureCRLSource);

		for (CRLBinaryIdentifier crlBinary : signatureCRLSource.getAllCRLIdentifiers()) {
			for (RevocationOrigin origin : crlBinary.getOrigins()) {
				addCRLBinary(crlBinary, origin);
			}
		}
		for (CRLRef crlRef : signatureCRLSource.getAllCRLReferences()) {
			addReference(crlRef, crlRef.getLocation());
		}
	}
	
	@Override
	protected void storeCRLToken(CRLBinaryIdentifier crlBinary, CRLToken crlToken) {
		if (crlsBinaryMap.containsKey(crlBinary.asXmlId())) {
			List<CRLToken> tokensList = crlTokenMap.get(crlBinary);
			if (tokensList == null) {
				tokensList = new ArrayList<CRLToken>();
				crlTokenMap.put(crlBinary, tokensList);
			}
			tokensList.add(crlToken);
			for (RevocationOrigin origin : crlBinary.getOrigins()) {
				addToRelevantList(crlToken, origin);
			}
		}
	}
	
	private void addToRelevantList(CRLToken crlToken, RevocationOrigin origin) {
		switch (origin) {
			case INTERNAL_REVOCATION_VALUES:
				revocationValuesCRLs.add(crlToken);
				break;
			case INTERNAL_ATTRIBUTE_REVOCATION_VALUES:
				attributeRevocationValuesCRLs.add(crlToken);
				break;
			case INTERNAL_TIMESTAMP_REVOCATION_VALUES:
				timestampRevocationValuesCRLs.add(crlToken);
				break;
			case INTERNAL_DSS:
				dssDictionaryCRLs.add(crlToken);
				break;
			case INTERNAL_VRI:
				vriDictionaryCRLs.add(crlToken);
			default:
				break;
		}
	}
	
	protected void addReference(CRLRef crlRef, RevocationOrigin origin) {
		switch (origin) {
		case COMPLETE_REVOCATION_REFS:
			if (!completeRevocationRefsCRLs.contains(crlRef)) {
				completeRevocationRefsCRLs.add(crlRef);
			}
			break;
		case ATTRIBUTE_REVOCATION_REFS:
			if (!attributeRevocationRefsCRLs.contains(crlRef)) {
				attributeRevocationRefsCRLs.add(crlRef);
			}
		case TIMESTAMP_REVOCATION_REFS:
			if (!timestampRevocationRefsCRLs.contains(crlRef)) {
				timestampRevocationRefsCRLs.add(crlRef);
			}
		default:
			break;
		}
	}
	
	/**
	 * Returns a list of {@link CRLRef}s assigned to the given {@code crlBinary}
	 * @param crlBinary {@link CRLBinaryIdentifier} to get references for
	 * @return list of {@link CRLRef}s
	 */
	public List<CRLRef> getReferencesForCRLIdentifier(CRLBinaryIdentifier crlBinary) {
		List<CRLRef> relatedRefs = new ArrayList<CRLRef>();
		for (CRLRef crlRef : getAllCRLReferences()) {
			byte[] digestValue = crlBinary.getDigestValue(crlRef.getDigestAlgorithm());
			if (Arrays.equals(crlRef.getDigestValue(), digestValue)) {
				relatedRefs.add(crlRef);
			}
		}
		return relatedRefs;
	}
	
	/**
	 * Returns a contained {@link CRLRef} with the given {@code digest}
	 * @param digest {@link Digest} to find a {@link CRLRef} with
	 * @return {@link CRLRef}
	 */
	public CRLRef getCRLRefByDigest(Digest digest) {
		for (CRLRef crlRef : getAllCRLReferences()) {
			if (digest.getAlgorithm().equals(crlRef.getDigestAlgorithm()) && Arrays.equals(digest.getValue(), crlRef.getDigestValue())) {
				return crlRef;
			}
		}
		return null;
	}
	
	/**
	 * Returns a list of orphan CRL Refs
	 * @return list of {@link CRLRef}s
	 */
	public List<CRLRef> getOrphanCrlRefs() {
		if (orphanRevocationRefsCRLs == null) {
			orphanRevocationRefsCRLs = new ArrayList<CRLRef>();
			for (CRLRef crlRef : getAllCRLReferences()) {
				if (getIdentifier(crlRef) == null) {
					orphanRevocationRefsCRLs.add(crlRef);
				}
			}
		}
		return orphanRevocationRefsCRLs;
	}

	/**
	 * Retrieves a list of found CRL Tokens for the given {@code revocationRefs}
	 * @param revocationRefs list of {@link CRLRef} to get tokens for
	 * @return list of {@link CRLToken}s
	 */
	public List<CRLToken> findTokensFromRefs(List<CRLRef> revocationRefs) {
		if (Utils.isMapEmpty(revocationRefsMap)) {
			collectRevocationRefsMap();
		}
		List<CRLToken> tokensFromRefs = new ArrayList<CRLToken>();
		for (Entry<CRLToken, Set<CRLRef>> revocationMapEntry : revocationRefsMap.entrySet()) {
			for (CRLRef tokenRevocationRef : revocationMapEntry.getValue()) {
				if (revocationRefs.contains(tokenRevocationRef)) {
					tokensFromRefs.add(revocationMapEntry.getKey());
					break;
				}
			}
		}
		return tokensFromRefs;
	}
	
	/**
	 * Retrieves a set of found CRL Refs for the given {@code revocationToken}
	 * @param revocationToken {@link CRLToken} to get references for
	 * @return list of {@link CRLRef}s
	 */
	public Set<CRLRef> findRefsForRevocationToken(CRLToken revocationToken) {
		if (Utils.isMapEmpty(revocationRefsMap)) {
			collectRevocationRefsMap();
		}
		Set<CRLRef> revocationRefs = revocationRefsMap.get(revocationToken);
		if (revocationRefs != null) {
			return revocationRefs;
		} else {
			return Collections.emptySet();
		}
	}
	
	private void collectRevocationRefsMap() {
		revocationRefsMap = new HashMap<CRLToken, Set<CRLRef>>();
		for (CRLToken revocationToken : getAllCRLTokens()) {
			for (CRLRef reference : getAllCRLReferences()) {
				if (Arrays.equals(reference.getDigestValue(), revocationToken.getDigest(reference.getDigestAlgorithm()))) {
					addReferenceToMap(revocationToken, reference);
				}
			}
		}
	}
	
	private void addReferenceToMap(CRLToken revocationToken, CRLRef reference) {
		if (revocationRefsMap.containsKey(revocationToken)) {
			revocationRefsMap.get(revocationToken).add(reference);
		} else {
			revocationRefsMap.put(revocationToken, new HashSet<CRLRef>(Arrays.asList(reference)));
		}
	}

}
