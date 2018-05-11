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

import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * Check the status of the certificate using an OCSPSource
 *
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
			final OCSPToken ocspToken = ocspSource.getOCSPToken(toCheckToken, toCheckToken.getIssuerToken());
			if (ocspToken == null) {
				LOG.debug("No matching OCSP response found for " + toCheckToken.getDSSIdAsString());
			} else {
				ocspToken.extractInfo();
				final boolean found = extractSigningCertificateFromResponse(ocspToken);
				if (!found) {
					extractSigningCertificateFormResponderId(ocspToken);
				}
				toCheckToken.addRevocationToken(ocspToken);
			}
			return ocspToken;
		} catch (DSSException e) {
			LOG.error("OCSP DSS Exception: " + e.getMessage(), e);
			toCheckToken.extraInfo().infoOCSPException(e.getMessage());
			return null;
		}
	}

	private boolean extractSigningCertificateFromResponse(OCSPToken ocspToken) {
		BasicOCSPResp basicOCSPResp = ocspToken.getBasicOCSPResp();
		if (basicOCSPResp != null) {
			for (final X509CertificateHolder x509CertificateHolder : basicOCSPResp.getCerts()) {
				CertificateToken certificateToken = DSSASN1Utils.getCertificate(x509CertificateHolder);
				CertificateToken certToken = validationCertPool.getInstance(certificateToken, CertificateSourceType.OCSP_RESPONSE);
				if (ocspToken.isSignedBy(certToken)) {
					return true;
				}
			}
		}
		return false;
	}

	private void extractSigningCertificateFormResponderId(OCSPToken ocspToken) {
		BasicOCSPResp basicOCSPResp = ocspToken.getBasicOCSPResp();
		if (basicOCSPResp != null) {
			final RespID responderId = basicOCSPResp.getResponderId();
			final ResponderID responderIdAsASN1Object = responderId.toASN1Primitive();
			final DERTaggedObject derTaggedObject = (DERTaggedObject) responderIdAsASN1Object.toASN1Primitive();
			if (1 == derTaggedObject.getTagNo()) {
				final ASN1Primitive derObject = derTaggedObject.getObject();
				final byte[] derEncoded = DSSASN1Utils.getDEREncoded(derObject);
				final X500Principal x500Principal_ = new X500Principal(derEncoded);
				final X500Principal x500Principal = DSSUtils.getNormalizedX500Principal(x500Principal_);
				final List<CertificateToken> certificateTokens = validationCertPool.get(x500Principal);
				for (final CertificateToken issuerCertificateToken : certificateTokens) {
					if (ocspToken.isSignedBy(issuerCertificateToken)) {
						break;
					}
				}
			} else if (2 == derTaggedObject.getTagNo()) {
				final ASN1OctetString hashOctetString = (ASN1OctetString) derTaggedObject.getObject();
				final byte[] expectedHash = hashOctetString.getOctets();
				final List<CertificateToken> certificateTokens = validationCertPool.getCertificateTokens();
				for (CertificateToken issuerCertificateToken : certificateTokens) {
					final byte[] ski = DSSASN1Utils.getSki(issuerCertificateToken, true);
					if (Arrays.equals(expectedHash, ski) && ocspToken.isSignedBy(issuerCertificateToken)) {
						break;
					}
				}
			} else {
				throw new DSSException("Unsupported tag No " + derTaggedObject.getTagNo());
			}
		}
	}

}
