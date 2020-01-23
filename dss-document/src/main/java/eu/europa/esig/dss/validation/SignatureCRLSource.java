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
package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;

@SuppressWarnings("serial")
public abstract class SignatureCRLSource extends OfflineCRLSource implements SignatureRevocationSource<CRLToken> {
	
	private Map<CRLBinary, List<CRLToken>> crlTokenMap = new HashMap<>();

	private List<CRLToken> cmsSignedDataCRLs = new ArrayList<>();
	private List<CRLToken> timestampSignedDataCRLs = new ArrayList<>();
	private List<CRLToken> revocationValuesCRLs = new ArrayList<>();
	private List<CRLToken> attributeRevocationValuesCRLs = new ArrayList<>();
	private List<CRLToken> timestampValidationDataCRLs = new ArrayList<>();
	private List<CRLToken> dssDictionaryCRLs = new ArrayList<>();
	private List<CRLToken> vriDictionaryCRLs = new ArrayList<>();
	private List<CRLToken> timestampRevocationValuesCRLs = new ArrayList<>();
	private List<CRLToken> adbeRevocationValuesCRLs = new ArrayList<>();
	
	private List<CRLRef> crlRefs = new ArrayList<>();
	
	private List<CRLRef> orphanRevocationRefsCRLs;
	
	/**
	 * Map that links {@link CRLToken}s with related {@link CRLRef}s
	 */
	private transient Map<CRLToken, Set<CRLRef>> revocationRefsMap;

	@Override
	public List<CRLToken> getCMSSignedDataRevocationTokens() {
		return cmsSignedDataCRLs;
	}

	@Override
	public List<CRLToken> getTimestampSignedDataRevocationTokens() {
		return timestampSignedDataCRLs;
	}

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
	
	@Override
	public List<CRLToken> getADBERevocationValuesTokens() {
		return adbeRevocationValuesCRLs;
	}

	public List<CRLRef> getCompleteRevocationRefs() {
		return getCRLRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
	}

	public List<CRLRef> getAttributeRevocationRefs() {
		return getCRLRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	public List<CRLRef> getTimestampRevocationRefs() {
		return getCRLRefsByOrigin(RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS);
	}
	
	private List<CRLRef> getCRLRefsByOrigin(RevocationRefOrigin origin) {
		List<CRLRef> revocationRefsCRLs = new ArrayList<>();
		for (CRLRef crlRef : crlRefs) {
			if (crlRef.getOrigins().contains(origin)) {
				revocationRefsCRLs.add(crlRef);
			}
		}
		return revocationRefsCRLs;
	}
	
	/**
	 * Retrieves all found CRL Tokens
	 * @return list of {@link CRLToken}s
	 */
	public List<CRLToken> getAllCRLTokens() {
		List<CRLToken> crlTokens = new ArrayList<>();
		crlTokens.addAll(getCMSSignedDataRevocationTokens());
		crlTokens.addAll(getTimestampSignedDataRevocationTokens());
		crlTokens.addAll(getRevocationValuesTokens());
		crlTokens.addAll(getAttributeRevocationValuesTokens());
		crlTokens.addAll(getTimestampValidationDataTokens());
		crlTokens.addAll(getDSSDictionaryTokens());
		crlTokens.addAll(getVRIDictionaryTokens());
		crlTokens.addAll(getTimestampRevocationValuesTokens());
		crlTokens.addAll(getADBERevocationValuesTokens());
		return crlTokens;
	}

	/**
	 * Retrieves all found CRL Refs
	 * @return list of {@link CRLRef}s
	 */
	public List<CRLRef> getAllCRLReferences() {
		return crlRefs;
	}
	
	@Override
	protected void storeCRLToken(CRLBinary crlBinary, CRLToken crlToken) {
		if (getCRLBinaryList().contains(crlBinary)) {
			List<CRLToken> tokensList = crlTokenMap.get(crlBinary);
			if (tokensList == null) {
				tokensList = new ArrayList<>();
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
		case CMS_SIGNED_DATA:
			cmsSignedDataCRLs.add(crlToken);
			break;
		case TIMESTAMP_SIGNED_DATA:
			timestampSignedDataCRLs.add(crlToken);
			break;
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
		case ADBE_REVOCATION_INFO_ARCHIVAL:
			adbeRevocationValuesCRLs.add(crlToken);
			break;
		default:
			throw new DSSException(
					String.format("The given RevocationOrigin [%s] is not supported for CRLToken object in the SignatureCRLSource", origin));
		}
	}
	
	protected void addReference(CRLRef crlRef, RevocationRefOrigin origin) {
		int index = crlRefs.indexOf(crlRef);
		if (index == -1) {
			crlRefs.add(crlRef);
		} else {
			CRLRef storedCRLRef = crlRefs.get(index);
			storedCRLRef.addOrigin(origin);
		}
	}
	
	/**
	 * Returns a list of {@link CRLRef}s assigned to the given {@code crlBinary}
	 * @param crlBinary {@link CRLBinary} to get references for
	 * @return list of {@link CRLRef}s
	 */
	public List<CRLRef> getReferencesForCRLIdentifier(CRLBinary crlBinary) {
		List<CRLRef> relatedRefs = new ArrayList<>();
		for (CRLRef crlRef : getAllCRLReferences()) {
			Digest refDigest = crlRef.getDigest();
			byte[] digestValue = crlBinary.getDigestValue(refDigest.getAlgorithm());
			if (Arrays.equals(refDigest.getValue(), digestValue)) {
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
			orphanRevocationRefsCRLs = new ArrayList<>();
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
		List<CRLToken> tokensFromRefs = new ArrayList<>();
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
		revocationRefsMap = new HashMap<>();
		for (CRLToken revocationToken : getAllCRLTokens()) {
			for (CRLRef reference : getAllCRLReferences()) {
				Digest refDigest = reference.getDigest();
				if (Arrays.equals(refDigest.getValue(), revocationToken.getDigest(refDigest.getAlgorithm()))) {
					addReferenceToMap(revocationToken, reference);
				}
			}
		}
	}
	
	private void addReferenceToMap(CRLToken revocationToken, CRLRef reference) {
		Set<CRLRef> crlRefs = revocationRefsMap.get(revocationToken);
		if (crlRefs == null) {
			crlRefs = new HashSet<>();
			revocationRefsMap.put(revocationToken, crlRefs);
		}
		crlRefs.add(reference);
	}

}
