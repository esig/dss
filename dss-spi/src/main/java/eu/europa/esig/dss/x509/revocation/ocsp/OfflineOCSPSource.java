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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 *
 */
@SuppressWarnings("serial")
public abstract class OfflineOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineOCSPSource.class);

	protected final Map<String, OCSPResponseIdentifier> ocspResponses = new HashMap<String, OCSPResponseIdentifier>();

	@Override
	public final OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		
		if (isEmpty()) {
			return null;
		}
		
		if (LOG.isTraceEnabled()) {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			LOG.trace("--> OfflineOCSPSource queried for {} contains: {} element(s).", dssIdAsString, ocspResponses.size());
		}

		Entry<BasicOCSPResp, List<RevocationOrigin>> bestOCSPResponse = findBestOcspResponse(certificateToken, issuerCertificateToken);
		if (bestOCSPResponse != null) {
			OCSPTokenBuilder ocspTokenBuilder = new OCSPTokenBuilder(bestOCSPResponse.getKey(), certificateToken, issuerCertificateToken);
			ocspTokenBuilder.setOrigins(bestOCSPResponse.getValue());
			try {
				OCSPToken ocspToken = ocspTokenBuilder.build();
				OCSPTokenUtils.checkTokenValidity(ocspToken, certificateToken, issuerCertificateToken);
				OCSPResponseIdentifier ocspResponse = OCSPResponseIdentifier.build(bestOCSPResponse.getKey(), bestOCSPResponse.getValue());
				storeOCSPToken(ocspResponse, ocspToken);
				return ocspToken;
			} catch (OCSPException e) {
				LOG.error("An error occurred during an attempt to build OCSP Token. Return null", e);
				return null;
			}
		}
		return null;
	}
	
	private Entry<BasicOCSPResp, List<RevocationOrigin>> findBestOcspResponse(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		Entry<BasicOCSPResp, List<RevocationOrigin>> bestOCSPResponse = null;
		Date bestUpdate = null;
		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken);
		for (final OCSPResponseIdentifier response : ocspResponses.values()) {
			for (final SingleResp singleResp : response.getBasicOCSPResp().getResponses()) {
				if (DSSRevocationUtils.matches(certId, singleResp)) {
					final Date thisUpdate = singleResp.getThisUpdate();
					if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {
						bestOCSPResponse = new AbstractMap.SimpleEntry<BasicOCSPResp, List<RevocationOrigin>>(
								response.getBasicOCSPResp(), response.getOrigins());
						bestUpdate = thisUpdate;
					} else if (thisUpdate.equals(bestUpdate)) {
						bestOCSPResponse.getValue().addAll(response.getOrigins());
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
	public Collection<OCSPResponseIdentifier> getOCSPResponsesList() {
		Collection<OCSPResponseIdentifier> ocspResponsesList = new ArrayList<OCSPResponseIdentifier>();
		if (!isEmpty()) {
			for (OCSPResponseIdentifier ocspResponse : ocspResponses.values()) {
				ocspResponsesList.add(ocspResponse);
			}
		}
		return Collections.unmodifiableCollection(ocspResponsesList);
	}
	
	public boolean isEmpty() {
		if (Utils.isMapEmpty(ocspResponses)) {
			appendContainedOCSPResponses();
		}
		return Utils.isMapEmpty(ocspResponses);
	}
	
	protected void storeOCSPToken(OCSPResponseIdentifier ocspResponse, OCSPToken ocspToken) {
		// do nothing
	}
	
	/**
	 * Returns all found in DSS and VRI dictionaries {@link OCSPResponseIdentifier}s
	 * @return collection of {@link OCSPResponseIdentifier}s
	 */
	public Collection<OCSPResponseIdentifier> getAllOCSPIdentifiers() {
		if (!isEmpty()) {
			return ocspResponses.values();
		}
		return Collections.emptyList();
	}
	
	/**
	  Returns the identifier related for the provided {@node ocspRef}
	 * @param ocspRef {@link OCSPRef} to find identifier for
	 * @return {@link OCSPResponseIdentifier} for the reference
	 */
	public OCSPResponseIdentifier getIdentifier(OCSPRef ocspRef) {
		return getIdentifier(new Digest(ocspRef.getDigestAlgorithm(), ocspRef.getDigestValue()));
	}
	
	/**
	 * Returns the identifier related for the provided {@node digest} of reference
	 * @param digest {@link Digest} of the reference
	 * @return {@link OCSPResponseIdentifier} for the reference
	 */
	public OCSPResponseIdentifier getIdentifier(Digest digest) {
		if (digest.getAlgorithm() == null || digest.getValue() == null) {
			return null;
		}
		for (OCSPResponseIdentifier ocspResponse : ocspResponses.values()) {
			byte[] digestValue = ocspResponse.getDigestValue(digest.getAlgorithm());
			if (Arrays.equals(digest.getValue(), digestValue)) {
				return ocspResponse;
			}
		}
		return null;
	}
	
	/**
	 * Adds the provided {@code ocspResponse} to the list
	 * @param ocspResponse {@link OCSPResponseIdentifier} to add
	 * @param origin {@link RevocationOrigin} of the {@code ocspResponse}
	 */
	protected void addOCSPResponse(OCSPResponseIdentifier ocspResponse, RevocationOrigin origin) {
		if (ocspResponses.containsKey(ocspResponse.asXmlId())) {
			OCSPResponseIdentifier storedOCSPResponse = ocspResponses.get(ocspResponse.asXmlId());
			storedOCSPResponse.addOrigin(origin);
		} else {
			ocspResponses.put(ocspResponse.asXmlId(), ocspResponse);
		}
	}

}
