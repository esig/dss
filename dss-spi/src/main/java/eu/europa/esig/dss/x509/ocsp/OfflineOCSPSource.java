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
package eu.europa.esig.dss.x509.ocsp;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;

/**
 * Abstract class that helps to implement an OCSPSource with an already loaded list of BasicOCSPResp
 *
 *
 */

public abstract class OfflineOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineOCSPSource.class);

	@Override
	final public OCSPToken getOCSPToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {

		final List<BasicOCSPResp> containedOCSPResponses = getContainedOCSPResponses();
		if (LOG.isTraceEnabled()) {
			final String dssIdAsString = certificateToken.getDSSIdAsString();
			LOG.trace("--> OfflineOCSPSource queried for " + dssIdAsString + " contains: " + containedOCSPResponses.size() + " element(s).");
		}
		final X509Certificate x509Certificate = certificateToken.getCertificate();
		final X509Certificate issuerX509Certificate = issuerCertificateToken.getCertificate();
		/**
		 * TODO: (Bob 2013.05.08) Does the OCSP responses always use SHA1?<br>
		 * RFC 2560:<br>
		 * CertID ::= SEQUENCE {<br>
		 * hashAlgorithm AlgorithmIdentifier,<br>
		 * issuerNameHash OCTET STRING, -- Hash of Issuer's DN<br>
		 * issuerKeyHash OCTET STRING, -- Hash of Issuer's public key<br>
		 * serialNumber CertificateSerialNumber }<br>
		 *
		 * ... The hash algorithm used for both these hashes, is identified in hashAlgorithm. serialNumber is the
		 * serial number of the cert for which status is being requested.
		 */
		Date bestUpdate = null;
		BasicOCSPResp bestBasicOCSPResp = null;
		SingleResp bestSingleResp = null;
		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(x509Certificate, issuerX509Certificate);
		for (final BasicOCSPResp basicOCSPResp : containedOCSPResponses) {

			for (final SingleResp singleResp : basicOCSPResp.getResponses()) {

				if (DSSRevocationUtils.matches(certId, singleResp)) {

					final Date thisUpdate = singleResp.getThisUpdate();
					if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {

						bestBasicOCSPResp = basicOCSPResp;
						bestSingleResp = singleResp;
						bestUpdate = thisUpdate;
					}
				}
			}
			if (bestBasicOCSPResp != null) {
				break;
			}
		}
		if (bestSingleResp != null) {

			final OCSPToken ocspToken = new OCSPToken(bestBasicOCSPResp, bestSingleResp);
			certificateToken.setRevocationToken(ocspToken);
			return ocspToken;
		}
		return null;
	}

	/**
	 * Retrieves the list of {@code BasicOCSPResp} contained in the source.
	 *
	 * @return {@code List} of {@code BasicOCSPResp}s
	 */
	public abstract List<BasicOCSPResp> getContainedOCSPResponses();
}
