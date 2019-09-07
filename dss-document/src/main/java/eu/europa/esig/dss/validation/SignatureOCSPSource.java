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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;

@SuppressWarnings("serial")
public abstract class SignatureOCSPSource extends OfflineOCSPSource implements SignatureRevocationSource<OCSPToken> {
	
	private Map<OCSPResponseBinary, OCSPToken> ocspTokenMap = new HashMap<OCSPResponseBinary, OCSPToken>();
	
	private final List<OCSPToken> revocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> attributeRevocationValuesOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> timestampValidationDataOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> dssDictionaryOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> vriDictionaryOCSPs = new ArrayList<OCSPToken>();
	private final List<OCSPToken> timestampRevocationValuesOCSPs = new ArrayList<OCSPToken>();
	
	private List<OCSPRef> ocspRefs = new ArrayList<OCSPRef>();
	
	private transient List<OCSPRef> orphanRevocationRefsOCSPs;
	
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
	public List<OCSPToken> getTimestampValidationDataTokens() {
		return timestampValidationDataOCSPs;
	}

	@Override
	public List<OCSPToken> getDSSDictionaryTokens() {
		return dssDictionaryOCSPs;
	}

	@Override
	public List<OCSPToken> getVRIDictionaryTokens() {
		return vriDictionaryOCSPs;
	}

	@Override
	public List<OCSPToken> getTimestampRevocationValuesTokens() {
		return timestampRevocationValuesOCSPs;
	}

	public List<OCSPRef> getCompleteRevocationRefs() {
		return getOCSPRefsByOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS);
	}

	public List<OCSPRef> getAttributeRevocationRefs() {
		return getOCSPRefsByOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS);
	}

	public List<OCSPRef> getTimestampRevocationRefs() {
		return getOCSPRefsByOrigin(RevocationRefOrigin.TIMESTAMP_REVOCATION_REFS);
	}
	
	private List<OCSPRef> getOCSPRefsByOrigin(RevocationRefOrigin origin) {
		List<OCSPRef> revocationRefsOCSPs = new ArrayList<OCSPRef>();
		for (OCSPRef ocspRef : ocspRefs) {
			if (ocspRef.getOrigins().contains(origin)) {
				revocationRefsOCSPs.add(ocspRef);
			}
		}
		return revocationRefsOCSPs;
	}
	
	/**
	 * Retrieves all found OCSP Tokens
	 * @return list of {@link OCSPToken}s
	 */
	public List<OCSPToken> getAllOCSPTokens() {
		List<OCSPToken> ocspTokens = new ArrayList<OCSPToken>();
		ocspTokens.addAll(getRevocationValuesTokens());
		ocspTokens.addAll(getAttributeRevocationValuesTokens());
		ocspTokens.addAll(getTimestampValidationDataTokens());
		ocspTokens.addAll(getDSSDictionaryTokens());
		ocspTokens.addAll(getVRIDictionaryTokens());
		ocspTokens.addAll(getTimestampRevocationValuesTokens());
		return ocspTokens;
	}

	/**
	 * Retrieves all found OCSP Refs
	 * @return list of {@link OCSPRef}s
	 */
	public List<OCSPRef> getAllOCSPReferences() {
		return ocspRefs;
	}
	
	public Map<OCSPResponseBinary, OCSPToken> getOCSPTokenMap() {
		return ocspTokenMap;
	}
	
	/**
	 * Allows to fill all OCSP missing revocation tokens from the given {@link SignatureOCSPSource}
	 * @param signatureOCSPSource {@link SignatureOCSPSource} to populate values from
	 */
	public void populateOCSPRevocationTokenLists(SignatureOCSPSource signatureOCSPSource) {
		for (Entry<OCSPResponseBinary, OCSPToken> entry : signatureOCSPSource.getOCSPTokenMap().entrySet()) {
			storeOCSPToken(entry);
		}
	}
	
	private void storeOCSPToken(Entry<OCSPResponseBinary, OCSPToken> responseTokenEntry) {
		storeOCSPToken(responseTokenEntry.getKey(), responseTokenEntry.getValue());
	}

	@Override
	protected void storeOCSPToken(OCSPResponseBinary ocspResponse, OCSPToken ocspToken) {
		if (getOCSPResponsesList().contains(ocspResponse) && !ocspTokenMap.containsKey(ocspResponse)) {
			ocspTokenMap.put(ocspResponse, ocspToken);
			for (RevocationOrigin origin : getRevocationOrigins(ocspResponse)) {
				switch (origin) {
				case REVOCATION_VALUES:
					revocationValuesOCSPs.add(ocspToken);
					break;
				case ATTRIBUTE_REVOCATION_VALUES:
					attributeRevocationValuesOCSPs.add(ocspToken);
					break;
				case TIMESTAMP_VALIDATION_DATA:
					timestampValidationDataOCSPs.add(ocspToken);
					break;
				case DSS_DICTIONARY:
					dssDictionaryOCSPs.add(ocspToken);
					break;
				case VRI_DICTIONARY:
					vriDictionaryOCSPs.add(ocspToken);
					break;
				case TIMESTAMP_REVOCATION_VALUES:
					timestampRevocationValuesOCSPs.add(ocspToken);
					break;
				default:
					throw new DSSException(
							String.format("The given RevocationOrigin [%s] is not supported for OCSPToken object in the SignatureOCSPSource", origin));
				}
			}
		}
	}
	
	protected void addReference(OCSPRef ocspRef) {
		for (RevocationRefOrigin origin : ocspRef.getOrigins()) {
			addReference(ocspRef, origin);
		}
	}

	protected void addReference(OCSPRef ocspRef, RevocationRefOrigin origin) {
		int index = ocspRefs.indexOf(ocspRef);
		if (index == -1) {
			ocspRefs.add(ocspRef);
		} else {
			OCSPRef storedOCSPRef = ocspRefs.get(index);
			storedOCSPRef.addOrigin(origin);
		}
	}
	
	/**
	 * Returns a list of {@link OCSPRef}s assigned to the given {@code ocspResponse}
	 * @param ocspResponse {@link OCSPResponseBinary} to get references for
	 * @return list of {@link OCSPRef}s
	 */
	public List<OCSPRef> getReferencesForOCSPIdentifier(OCSPResponseBinary ocspResponse) {
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
		Set<OCSPRef> ocspRefs = revocationRefsMap.get(revocationToken);
		if (ocspRefs == null) {
			ocspRefs = new HashSet<OCSPRef>();
			revocationRefsMap.put(revocationToken, ocspRefs);
		}
		ocspRefs.add(reference);
	}

}
