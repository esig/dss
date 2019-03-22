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
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Map.Entry;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 *
 */
@SuppressWarnings("serial")
public abstract class OfflineOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineOCSPSource.class);

	protected final List<OCSPResponse> ocspResponses = new ArrayList<OCSPResponse>();

	@Override
	public final OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		
		if (ocspResponses.isEmpty()) {
			appendContainedOCSPResponses();
			if (ocspResponses.isEmpty()) {
				return null;
			}
		}
		
		if (LOG.isTraceEnabled()) {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			LOG.trace("--> OfflineOCSPSource queried for {} contains: {} element(s).", dssIdAsString, ocspResponses.size());
		}

		Entry<BasicOCSPResp, List<RevocationOrigin>> bestOCSPResponse = findBestOcspResponse(certificateToken, issuerCertificateToken);
		if (bestOCSPResponse != null) {
			OCSPTokenBuilder ocspTokenBuilder = new OCSPTokenBuilder(bestOCSPResponse.getKey(), certificateToken, issuerCertificateToken);
			ocspTokenBuilder.setOrigin(bestOCSPResponse.getValue().get(0));
			try {
				OCSPToken ocspToken = ocspTokenBuilder.build();
				OCSPTokenUtils.checkTokenValidity(ocspToken, certificateToken, issuerCertificateToken);
				for (RevocationOrigin origin : bestOCSPResponse.getValue()) {
					OCSPResponse ocspResponse = new OCSPResponse(bestOCSPResponse.getKey(), origin);
					storeOCSPToken(ocspResponse, ocspToken);
				}
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
		for (final OCSPResponse response : ocspResponses) {
			for (final SingleResp singleResp : response.getBasicOCSPResp().getResponses()) {
				if (DSSRevocationUtils.matches(certId, singleResp)) {
					final Date thisUpdate = singleResp.getThisUpdate();
					if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {
						bestOCSPResponse = new AbstractMap.SimpleEntry<BasicOCSPResp, List<RevocationOrigin>>(
								response.getBasicOCSPResp(), new ArrayList<>(Arrays.asList(response.getOrigin())));
						bestUpdate = thisUpdate;
					} else if (thisUpdate.equals(bestUpdate)) {
						bestOCSPResponse.getValue().add(response.getOrigin());
					}
				}
			}
		}
		return bestOCSPResponse;
	}
	
	/**
	 * Returns list containing all OCSP responses
	 * @return list of {@code OCSPResponse}s
	 */
	public List<OCSPResponse> getOCSPResponsesList() {
		if (ocspResponses.isEmpty()) {
			appendContainedOCSPResponses();
		}
		return ocspResponses;
	}
	
	/**
	 * Retrieves a list of {@code BasicOCSPResp}s contained in the source
	 * @return list of {@code BasicOCSPResp}s
	 */
	public Set<BasicOCSPResp> getBasicOCSPResponses() {
		if (ocspResponses.isEmpty()) {
			appendContainedOCSPResponses();
		}
		Set<BasicOCSPResp> basicOCSPRespSet = new HashSet<BasicOCSPResp>();
		for (OCSPResponse ocspResponse : ocspResponses) {
			basicOCSPRespSet.add(ocspResponse.getBasicOCSPResp());
		}
		return basicOCSPRespSet;
	}

	/**
	 * Retrieves the map of {@code BasicOCSPResp}/{@code RevocationOrigin} contained in the source and appends result entries to {@code ocspResponses}.
	 */
	public abstract void appendContainedOCSPResponses();
	
	protected void storeOCSPToken(OCSPResponse ocspResponse, OCSPToken ocspToken) {
		// do nothing
	}

}
