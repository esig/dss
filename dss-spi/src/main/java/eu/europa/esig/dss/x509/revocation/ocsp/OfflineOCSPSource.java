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

import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
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

	@Override
	public final OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		
		final List<BasicOCSPResp> containedOCSPResponses = getContainedOCSPResponses();
		if (Utils.isCollectionEmpty(containedOCSPResponses)) {
			return null;
		}
		
		if (LOG.isTraceEnabled()) {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			LOG.trace("--> OfflineOCSPSource queried for {} contains: {} element(s).", dssIdAsString, containedOCSPResponses.size());
		}

		BasicOCSPResp bestBasicOCSPResp = findBestOcspResponse(containedOCSPResponses, certificateToken, issuerCertificateToken);
		if (bestBasicOCSPResp != null) {
			OCSPTokenBuilder ocspTokenBuilder = new OCSPTokenBuilder(bestBasicOCSPResp, certificateToken, issuerCertificateToken);
			ocspTokenBuilder.setOrigin(RevocationOrigin.SIGNATURE);
			try {
				OCSPToken ocspToken = ocspTokenBuilder.build();
				OCSPTokenUtils.checkTokenValidity(ocspToken, certificateToken, issuerCertificateToken);
				return ocspToken;
			} catch (OCSPException e) {
				LOG.error("An error occurred during an attempt to build OCSP Token. Return null", e);
				return null;
			}
		}
		return null;
	}
	
	private BasicOCSPResp findBestOcspResponse(List<BasicOCSPResp> containedOCSPResponses, CertificateToken certificateToken, 
			CertificateToken issuerCertificateToken) {
		BasicOCSPResp bestBasicOCSPResp = null;
		Date bestUpdate = null;
		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken);
		for (final BasicOCSPResp basicOCSPResp : containedOCSPResponses) {
			for (final SingleResp singleResp : basicOCSPResp.getResponses()) {
				if (DSSRevocationUtils.matches(certId, singleResp)) {
					final Date thisUpdate = singleResp.getThisUpdate();
					if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {
						bestBasicOCSPResp = basicOCSPResp;
						bestUpdate = thisUpdate;
					}
				}
			}
		}
		return bestBasicOCSPResp;
	}

	/**
	 * Retrieves the list of {@code BasicOCSPResp} contained in the source.
	 *
	 * @return {@code List} of {@code BasicOCSPResp}s
	 */
	public abstract List<BasicOCSPResp> getContainedOCSPResponses();

}
