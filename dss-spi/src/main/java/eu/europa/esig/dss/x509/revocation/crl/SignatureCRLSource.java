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

import eu.europa.esig.dss.CRLBinary;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.revocation.SignatureRevocationSource;

@SuppressWarnings("serial")
public abstract class SignatureCRLSource extends OfflineCRLSource implements SignatureRevocationSource<CRLToken> {
	
	private Map<CRLBinary, List<CRLToken>> crlTokenMap = new HashMap<CRLBinary, List<CRLToken>>();
	
	private List<CRLToken> revocationValuesCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> attributeRevocationValuesCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> timestampValidationDataCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> dssDictionaryCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> vriDictionaryCRLs = new ArrayList<CRLToken>();
	private List<CRLToken> timestampRevocationValuesCRLs = new ArrayList<CRLToken>();
	
	private List<CRLRef> completeRevocationRefsCRLs = new ArrayList<CRLRef>();
	private List<CRLRef> attributeRevocationRefsCRLs = new ArrayList<CRLRef>();
	private List<CRLRef> timestampRevocationRefsCRLs = new ArrayList<CRLRef>();
	
	private List<CRLRef> orphanRevocationRefsCRLs;
	
	/**
	 * Map that links {@link CRLToken}s with related {@link CRLRef}s
	 */
	private transient Map<CRLToken, Set<CRLRef>> revocationRefsMap;

	@Override
	public List<CRLToken> getRevocationValuesTokens() {
		return revocationValuesCRLs;
	}

	@Override
	public List<CRLToken> getAttributeRevocationValuesTokens() {
		return attributeRevocationValuesCRLs;
	}

	@Override
	public List<CRLToken> getTimestampValidationDataTokens() {
		return timestampValidationDataCRLs;
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
		crlTokens.addAll(getTimestampValidationDataTokens());
		crlTokens.addAll(getDSSDictionaryTokens());
		crlTokens.addAll(getVRIDictionaryTokens());
		crlTokens.addAll(getTimestampRevocationValuesTokens());
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
	
	public Map<CRLBinary, List<CRLToken>> getCRLTokenMap() {
		return crlTokenMap;
	}
	
	/**
	 * Allows to fill all CRL missing revocation values from the given {@code signatureCRLSource}
	 * @param signatureCRLSource {@link SignatureCRLSource} to populate values from
	 */
	public void populateCRLRevocationValues(SignatureCRLSource signatureCRLSource) {
		for (Entry<CRLBinary, List<CRLToken>> entry : signatureCRLSource.getCRLTokenMap().entrySet()) {
			for (CRLToken crlToken : entry.getValue()) {
				storeCRLToken(entry.getKey(), crlToken);
			}
		}
	}
	
	@Override
	protected void storeCRLToken(CRLBinary crlBinary, CRLToken crlToken) {
		if (getCRLBinaryList().contains(crlBinary)) {
			List<CRLToken> tokensList = crlTokenMap.get(crlBinary);
			if (tokensList == null) {
				tokensList = new ArrayList<CRLToken>();
				crlTokenMap.put(crlBinary, tokensList);
			}
			tokensList.add(crlToken);
			for (RevocationOrigin origin : getRevocationOrigins(crlBinary)) {
				addToRelevantList(crlToken, origin);
			}
		}
	}
	
	private void addToRelevantList(CRLToken crlToken, RevocationOrigin origin) {
		switch (origin) {
		case REVOCATION_VALUES:
			revocationValuesCRLs.add(crlToken);
			break;
		case ATTRIBUTE_REVOCATION_VALUES:
			attributeRevocationValuesCRLs.add(crlToken);
			break;
		case TIMESTAMP_VALIDATION_DATA:
			timestampValidationDataCRLs.add(crlToken);
			break;
		case DSS_DICTIONARY:
			dssDictionaryCRLs.add(crlToken);
			break;
		case VRI_DICTIONARY:
			vriDictionaryCRLs.add(crlToken);
			break;
		case TIMESTAMP_REVOCATION_VALUES:
			timestampRevocationValuesCRLs.add(crlToken);
			break;
		default:
			throw new DSSException(
					String.format("The given RevocationOrigin [%s] is not supported for CRLToken object in the SignatureCRLSource", origin));
		}
	}
	
	protected void addReference(CRLRef crlRef, RevocationRefOrigin origin) {
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
			break;
		case TIMESTAMP_REVOCATION_REFS:
			if (!timestampRevocationRefsCRLs.contains(crlRef)) {
				timestampRevocationRefsCRLs.add(crlRef);
			}
			break;
		default:
			throw new DSSException(String.format("The given RevocationOrigin [%s] is not supported for CRLRef object in the SignatureCRLSource", origin));
		}
	}
	
	/**
	 * Returns a list of {@link CRLRef}s assigned to the given {@code crlBinary}
	 * @param crlBinary {@link CRLBinary} to get references for
	 * @return list of {@link CRLRef}s
	 */
	public List<CRLRef> getReferencesForCRLIdentifier(CRLBinary crlBinary) {
		List<CRLRef> relatedRefs = new ArrayList<CRLRef>();
		for (CRLRef crlRef : getAllCRLReferences()) {
			byte[] digestValue = crlBinary.getDigestValue(crlRef.getDigest().getAlgorithm());
			if (Arrays.equals(crlRef.getDigest().getValue(), digestValue)) {
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
			if (digest.equals(crlRef.getDigest())) {
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
				if (Arrays.equals(reference.getDigest().getValue(), revocationToken.getDigest(reference.getDigest().getAlgorithm()))) {
					addReferenceToMap(revocationToken, reference);
				}
			}
		}
	}
	
	private void addReferenceToMap(CRLToken revocationToken, CRLRef reference) {
		Set<CRLRef> crlRefs = revocationRefsMap.get(revocationToken);
		if (crlRefs == null) {
			crlRefs = new HashSet<CRLRef>();
			revocationRefsMap.put(revocationToken, crlRefs);
		}
		crlRefs.add(reference);
	}

}
