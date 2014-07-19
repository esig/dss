/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OnlineOCSPSource;

/**
 * Check the status of the certificate using an OCSPSource
 *
 * @version $Revision: 1757 $ - $Date: 2013-03-14 20:33:28 +0100 (Thu, 14 Mar 2013) $
 */

public class OCSPCertificateVerifier implements CertificateStatusVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPCertificateVerifier.class);

	private final OCSPSource ocspSource;

	private final CertificatePool validationCertPool;

	/**
	 * Create a CertificateVerifier that will use the OCSP Source for checking revocation data. The default constructor
	 * for OCSPCertificateVerifier.
	 *
	 * @param ocspSource
	 * @param validationCertPool
	 */
	public OCSPCertificateVerifier(final OCSPSource ocspSource, final CertificatePool validationCertPool) {

		this.ocspSource = ocspSource;
		this.validationCertPool = validationCertPool;
	}

	@Override
	public RevocationToken check(final CertificateToken toCheckToken) {

		if (ocspSource == null) {

			LOG.warn("OCSPSource null");
			toCheckToken.extraInfo().infoOCSPSourceIsNull();
			return null;
		}
		try {

			final X509Certificate issuerCert = toCheckToken.getIssuerToken().getCertificate();
			final X509Certificate toCheckCert = toCheckToken.getCertificate();
			final BasicOCSPResp basicOCSPResp = ocspSource.getOCSPResponse(toCheckCert, issuerCert);
			if (basicOCSPResp == null) {

				String uri = "";
				if (ocspSource instanceof OnlineOCSPSource) {

					uri = ((OnlineOCSPSource) ocspSource).getAccessLocation(toCheckCert);
					toCheckToken.extraInfo().infoNoOCSPResponse(uri);
				}

				if (LOG.isInfoEnabled()) {
					LOG.info("OCSP response not found for " + toCheckToken.getDSSIdAsString() + " [" + uri + "]");
				}
				return null;
			}
			final BigInteger serialNumber = toCheckCert.getSerialNumber();
			final X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(DSSUtils.getEncoded(issuerCert));
			final DigestCalculator digestCalculator = DSSUtils.getSHA1DigestCalculator();
			final CertificateID certificateId = new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
			final SingleResp[] singleResps = basicOCSPResp.getResponses();
			for (final SingleResp singleResp : singleResps) {
				if (!DSSRevocationUtils.matches(certificateId, singleResp)) {

					continue;
				}
				if (LOG.isDebugEnabled()) {

					LOG.debug("OCSP thisUpdate: " + singleResp.getThisUpdate());
					LOG.debug("OCSP nextUpdate: " + singleResp.getNextUpdate());
				}
				final OCSPToken ocspToken = new OCSPToken(basicOCSPResp, validationCertPool);
				if (ocspSource instanceof OnlineOCSPSource) {

					ocspToken.setSourceURI(((OnlineOCSPSource) ocspSource).getAccessLocation(toCheckCert));
				}

				ocspToken.setIssuingTime(basicOCSPResp.getProducedAt());
				toCheckToken.setRevocationToken(ocspToken);
				final Object certStatus = singleResp.getCertStatus();
				if (certStatus == null) {

					if (LOG.isInfoEnabled()) {
						LOG.info("OCSP OK for: " + toCheckToken.getDSSIdAsString());
						if (LOG.isTraceEnabled()) {
							LOG.trace("CertificateToken:\n{}", toCheckToken.toString());
						}
					}
					ocspToken.setStatus(true);
				} else {

					if (LOG.isInfoEnabled()) {
						LOG.info("OCSP certificate status: " + certStatus.getClass().getName());
					}
					if (certStatus instanceof RevokedStatus) {

						if (LOG.isInfoEnabled()) {
							LOG.info("OCSP status revoked");
						}
						final RevokedStatus revokedStatus = (RevokedStatus) certStatus;
						ocspToken.setStatus(false);
						ocspToken.setRevocationDate(revokedStatus.getRevocationTime());
						final int reasonId = revokedStatus.getRevocationReason();
						final CRLReason crlReason = CRLReason.lookup(reasonId);
						ocspToken.setReason(crlReason.toString());
					} else if (certStatus instanceof UnknownStatus) {

						if (LOG.isInfoEnabled()) {
							LOG.info("OCSP status unknown");
						}
						ocspToken.setReason("OCSP status: unknown");
					}
				}
				return ocspToken;
			}
		} catch (DSSException e) {

			LOG.error("OCSP DSS Exception: " + e.getMessage(), e);
			toCheckToken.extraInfo().infoOCSPException(e);
			return null;
		} catch (OCSPException e) {

			LOG.error("OCSP Exception: " + e.getMessage());
			toCheckToken.extraInfo().infoOCSPException(e);
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
		if (LOG.isInfoEnabled()) {
			LOG.debug("No matching OCSP response entry");
		}
		toCheckToken.extraInfo().infoNoOCSPResponse(null);
		return null;
	}
}
