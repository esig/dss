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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.util.Date;
import java.util.Set;

import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.identifier.MultipleDigestIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationContainer;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 *
 */
@SuppressWarnings("serial")
public abstract class OfflineOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineOCSPSource.class);

	/**
	 * Container with all revocation data
	 */
	protected final RevocationContainer<OCSP> container = new RevocationContainer<OCSP>(new OCSPTokenRefMatcher());

	@Override
	public final OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		
		final Set<MultipleDigestIdentifier> collectedBinaries = container.getCollectedBinaries();

		if (collectedBinaries.isEmpty()) {
			LOG.trace("Collection of embedded OCSP responses is empty");
			return null;
		}
		
		if (LOG.isTraceEnabled()) {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			LOG.trace("--> OfflineOCSPSource queried for {} contains: {} element(s).", dssIdAsString, collectedBinaries.size());
		}

		OCSPResponseBinary bestOCSPResponse = findBestOcspResponse(certificateToken, issuerCertificateToken, collectedBinaries);
		if (bestOCSPResponse != null) {
			OCSPToken ocspToken = new OCSPToken(bestOCSPResponse.getBasicOCSPResp(), certificateToken, issuerCertificateToken);
			storeOCSPToken(ocspToken, bestOCSPResponse);
			return ocspToken;
		} else if (LOG.isDebugEnabled()) {
			LOG.debug("Best OCSP Response for the certificate {} is not found", certificateToken.getDSSIdAsString());
		}
		return null;
	}
	
	private OCSPResponseBinary findBestOcspResponse(CertificateToken certificateToken, CertificateToken issuerCertificateToken,
			Set<MultipleDigestIdentifier> collectedBinaries) {
		OCSPResponseBinary bestOCSPResponse = null;
		Date bestUpdate = null;
		for (final MultipleDigestIdentifier binary : collectedBinaries) {
			OCSPResponseBinary response = (OCSPResponseBinary) binary;
			for (final SingleResp singleResp : response.getBasicOCSPResp().getResponses()) {
				DigestAlgorithm usedDigestAlgorithm = DSSRevocationUtils.getUsedDigestAlgorithm(singleResp);
				final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken, usedDigestAlgorithm);
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
	
	private void storeOCSPToken(OCSPToken ocspToken, OCSPResponseBinary binary) {
		container.addRevocation(ocspToken, binary);
	}

	/**
	 * Adds the provided {@code ocspResponse} to the list
	 * 
	 * @param ocspResponse {@link OCSPResponseBinary} to add
	 * @param origin       {@link RevocationOrigin} of the {@code ocspResponse}
	 */
	protected void addOCSPResponse(OCSPResponseBinary ocspResponse, RevocationOrigin origin) {
		container.addBinary(ocspResponse, origin);
	}

	/**
	 * Adds the provided {@code ocspResponse} to the list
	 * 
	 * @param ocspRef {@link OCSPRef} to add
	 * @param origin  {@link RevocationRefOrigin} of the {@code ocspRef}
	 */
	protected void addOCSPReference(OCSPRef ocspRef, RevocationRefOrigin origin) {
		container.addRevocationReference(ocspRef, origin);
	}

}
