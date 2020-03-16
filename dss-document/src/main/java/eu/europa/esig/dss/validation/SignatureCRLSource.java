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
public abstract class SignatureCRLSource extends OfflineCRLSource implements SignatureRevocationSource<CRLToken, CRLRef> {
	
	private Map<CRLBinary, List<CRLToken>> crlTokenMap = new HashMap<>();

	private List<CRLToken> cmsSignedDataCRLs = new ArrayList<>();
	private List<CRLToken> revocationValuesCRLs = new ArrayList<>();
	private List<CRLToken> attributeRevocationValuesCRLs = new ArrayList<>();
	private List<CRLToken> timestampValidationDataCRLs = new ArrayList<>();
	private List<CRLToken> dssDictionaryCRLs = new ArrayList<>();
	private List<CRLToken> vriDictionaryCRLs = new ArrayList<>();
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
 
	@Override
	public List<CRLRef> getCompleteRevocationRefs() {
		return getCRLRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
	}

	@Override
	public List<CRLRef> getAttributeRevocationRefs() {
		return getCRLRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
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
	
	@Override
	public List<CRLToken> getAllRevocationTokens() {
		List<CRLToken> crlTokens = new ArrayList<>();
		crlTokens.addAll(getCMSSignedDataRevocationTokens());
		crlTokens.addAll(getRevocationValuesTokens());
		crlTokens.addAll(getAttributeRevocationValuesTokens());
		crlTokens.addAll(getTimestampValidationDataTokens());
		crlTokens.addAll(getDSSDictionaryTokens());
		crlTokens.addAll(getVRIDictionaryTokens());
		crlTokens.addAll(getADBERevocationValuesTokens());
		return crlTokens;
	}

	@Override
	public List<CRLRef> getAllRevocationReferences() {
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
		for (CRLRef crlRef : getAllRevocationReferences()) {
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
		for (CRLRef crlRef : getAllRevocationReferences()) {
			if (digest.equals(crlRef.getDigest())) {
				return crlRef;
			}
		}
		return null;
	}
	
	@Override
	public List<CRLRef> getOrphanRevocationReferences() {
		if (orphanRevocationRefsCRLs == null) {
			orphanRevocationRefsCRLs = new ArrayList<>();
			for (CRLRef crlRef : getAllRevocationReferences()) {
				if (getIdentifier(crlRef) == null) {
					orphanRevocationRefsCRLs.add(crlRef);
				}
			}
		}
		return orphanRevocationRefsCRLs;
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
		for (CRLToken revocationToken : getAllRevocationTokens()) {
			for (CRLRef reference : getAllRevocationReferences()) {
				Digest refDigest = reference.getDigest();
				if (Arrays.equals(refDigest.getValue(), revocationToken.getDigest(refDigest.getAlgorithm()))) {
					addReferenceToMap(revocationToken, reference);
				}
			}
		}
	}
	
	private void addReferenceToMap(CRLToken revocationToken, CRLRef reference) {
		Set<CRLRef> currentCrlRefs = revocationRefsMap.get(revocationToken);
		if (currentCrlRefs == null) {
			currentCrlRefs = new HashSet<>();
			revocationRefsMap.put(revocationToken, currentCrlRefs);
		}
		currentCrlRefs.add(reference);
	}

}
