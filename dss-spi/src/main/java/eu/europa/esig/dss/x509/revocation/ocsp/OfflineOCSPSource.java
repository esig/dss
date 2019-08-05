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
package eu.europa.esig.dss.x509.revocation.ocsp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 *
 */
@SuppressWarnings("serial")
public abstract class OfflineOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineOCSPSource.class);

	/**
	 * This {@code Map} contains all collected OCSP responses with a set of their origins
	 */
	private final Map<OCSPResponseBinary, Set<RevocationOrigin>> ocspResponseOriginsMap = new HashMap<OCSPResponseBinary, Set<RevocationOrigin>>();

	@Override
	public final OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		
		if (isEmpty()) {
			return null;
		}
		
		if (LOG.isTraceEnabled()) {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			LOG.trace("--> OfflineOCSPSource queried for {} contains: {} element(s).", dssIdAsString, ocspResponseOriginsMap.size());
		}

		OCSPResponseBinary bestOCSPResponse = findBestOcspResponse(certificateToken, issuerCertificateToken);
		if (bestOCSPResponse != null) {
			OCSPTokenBuilder ocspTokenBuilder = new OCSPTokenBuilder(bestOCSPResponse.getBasicOCSPResp(), certificateToken, issuerCertificateToken);
			try {
				OCSPToken ocspToken = ocspTokenBuilder.build();
				OCSPTokenUtils.checkTokenValidity(ocspToken, certificateToken, issuerCertificateToken);
				storeOCSPToken(bestOCSPResponse, ocspToken);
				ocspToken.setOrigins(getRevocationOrigins(bestOCSPResponse));
				return ocspToken;
			} catch (OCSPException e) {
				LOG.error("An error occurred during an attempt to build OCSP Token. Return null", e);
				return null;
			}
		}
		return null;
	}
	
	private OCSPResponseBinary findBestOcspResponse(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		OCSPResponseBinary bestOCSPResponse = null;
		Date bestUpdate = null;
		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken);
		for (final OCSPResponseBinary response : ocspResponseOriginsMap.keySet()) {
			for (final SingleResp singleResp : response.getBasicOCSPResp().getResponses()) {
				if (DSSRevocationUtils.matches(certId, singleResp)) {
					final Date thisUpdate = singleResp.getThisUpdate();
					if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {
						bestOCSPResponse = response;
						bestUpdate = thisUpdate;
					}
				}
			}
		}
		return bestOCSPResponse;
	}

	/**
	 * Retrieves the map of {@code BasicOCSPResp}/{@code RevocationOrigin} contained in the source and appends result entries to {@code ocspResponses}.
	 */
	public abstract void appendContainedOCSPResponses();

	/**
	 * Returns a collection containing all OCSP responses
	 * @return unmodifiable collection of {@code OCSPResponse}s
	 */
	public Collection<OCSPResponseBinary> getOCSPResponsesList() {
		Collection<OCSPResponseBinary> ocspResponsesList = new ArrayList<OCSPResponseBinary>();
		if (!isEmpty()) {
			ocspResponsesList = ocspResponseOriginsMap.keySet();
		}
		return Collections.unmodifiableCollection(ocspResponsesList);
	}
	
	public boolean isEmpty() {
		if (Utils.isMapEmpty(ocspResponseOriginsMap)) {
			appendContainedOCSPResponses();
		}
		return Utils.isMapEmpty(ocspResponseOriginsMap);
	}
	
	protected void storeOCSPToken(OCSPResponseBinary ocspResponse, OCSPToken ocspToken) {
		// do nothing
	}
	
	/**
	 * Returns the identifier related for the provided {@code ocspRef}
	 * @param ocspRef {@link OCSPRef} to find identifier for
	 * @return {@link OCSPResponseBinary} for the reference
	 */
	public OCSPResponseBinary getIdentifier(OCSPRef ocspRef) {
		if (ocspRef.getDigest() != null) {
			return getIdentifier(ocspRef.getDigest());
		} else {
			for (OCSPResponseBinary ocspResponse : ocspResponseOriginsMap.keySet()) {
				if (ocspRef.getProducedAt().equals(ocspResponse.getBasicOCSPResp().getProducedAt())) {
					ResponderID responderID = ocspResponse.getBasicOCSPResp().getResponderId().toASN1Primitive();
					if (ocspRef.getResponderId().getKey() != null &&
							Arrays.equals(ocspRef.getResponderId().getKey(), responderID.getKeyHash()) ||
						ocspRef.getResponderId().getName() != null && responderID.getName() != null &&
						ocspRef.getResponderId().getName().equals(responderID.getName().toString())) {
						return ocspResponse;
					}
				}
			}
		}
		return null;
	}
	
	/**
	 * Returns the identifier related for the provided {@code digest} of reference
	 * @param digest {@link Digest} of the reference
	 * @return {@link OCSPResponseBinary} for the reference
	 */
	public OCSPResponseBinary getIdentifier(Digest digest) {
		if (digest == null) {
			return null;
		}
		for (OCSPResponseBinary ocspResponse : ocspResponseOriginsMap.keySet()) {
			byte[] digestValue = ocspResponse.getDigestValue(digest.getAlgorithm());
			if (Arrays.equals(digest.getValue(), digestValue)) {
				return ocspResponse;
			}
		}
		return null;
	}
	
	/**
	 * Adds the provided {@code ocspResponse} to the list
	 * @param ocspResponse {@link OCSPResponseBinary} to add
	 * @param origin {@link RevocationOrigin} of the {@code ocspResponse}
	 */
	protected void addOCSPResponse(OCSPResponseBinary ocspResponse, RevocationOrigin origin) {
		Set<RevocationOrigin> origins = ocspResponseOriginsMap.get(ocspResponse);
		if (origins == null) {
			origins = new HashSet<RevocationOrigin>();
			ocspResponseOriginsMap.put(ocspResponse, origins);
		}
		origins.add(origin);
	}
	
	/**
	 * Returns a set of {@code RevocationOrigin}s for the given {@code ocspResponse}
	 * @param ocspResponse {@link OCSPResponseBinary} to get origins for
	 * @return set of {@link RevocationOrigin}s
	 */
	public Set<RevocationOrigin> getRevocationOrigins(OCSPResponseBinary ocspResponse) {
		return ocspResponseOriginsMap.get(ocspResponse);
	}

}
