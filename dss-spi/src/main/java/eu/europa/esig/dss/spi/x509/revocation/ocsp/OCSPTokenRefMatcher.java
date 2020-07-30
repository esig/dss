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

import java.util.Arrays;

import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationTokenRefMatcher;

public class OCSPTokenRefMatcher implements RevocationTokenRefMatcher<OCSP> {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPTokenRefMatcher.class);

	@Override
	public boolean match(RevocationToken<OCSP> token, RevocationRef<OCSP> reference) {
		final OCSPToken ocspToken = (OCSPToken) token;
		final OCSPRef ocspRef = (OCSPRef) reference;

		if (ocspRef.getDigest() != null) {
			return matchByDigest(ocspToken, ocspRef.getDigest());
		} else {
			return matchByProperties(ocspToken, ocspRef);
		}
	}

	@Override
	public boolean match(EncapsulatedRevocationTokenIdentifier identifier, RevocationRef<OCSP> reference) {
		if (identifier instanceof OCSPResponseBinary) {
			final OCSPResponseBinary ocspResponseBinary = (OCSPResponseBinary) identifier;
			final OCSPRef ocspRef = (OCSPRef) reference;
			
			if (ocspRef.getDigest() != null) {
				return matchByDigest(ocspResponseBinary, ocspRef.getDigest());
			} else {
				return matchByProperties(ocspResponseBinary, ocspRef);
			}
		}
		return false;
	}

	private boolean matchByDigest(OCSPToken ocspToken, Digest digestToFind) {
		return Arrays.equals(digestToFind.getValue(), ocspToken.getDigest(digestToFind.getAlgorithm()));
	}

	private boolean matchByDigest(OCSPResponseBinary ocspResponseBinary, Digest digestToFind) {
		return Arrays.equals(digestToFind.getValue(), ocspResponseBinary.getDigestValue(digestToFind.getAlgorithm()));
	}

	private boolean matchByProperties(OCSPToken ocspToken, OCSPRef ocspRef) {
		if (ocspRef.getProducedAt().equals(ocspToken.getProductionDate())) {
            ResponderID tokenResponderId = ocspToken.getBasicOCSPResp().getResponderId().toASN1Primitive();
            ResponderId refResponderId = ocspRef.getResponderId();
            if (matchByKeyHash(tokenResponderId, refResponderId) || matchByName(tokenResponderId, refResponderId)) {
                return true;
            }
		}
		return false;
	}

	private boolean matchByProperties(OCSPResponseBinary ocspResponseBinary, OCSPRef ocspRef) {
		try {
			BasicOCSPResp basicOCSPResp = ocspResponseBinary.getBasicOCSPResp();
			if (ocspRef.getProducedAt().equals(basicOCSPResp.getProducedAt())) {
				ResponderID tokenResponderId = basicOCSPResp.getResponderId().toASN1Primitive();
	            ResponderId refResponderId = ocspRef.getResponderId();
	            if (matchByKeyHash(tokenResponderId, refResponderId) || matchByName(tokenResponderId, refResponderId)) {
	                return true;
	            }
			}
		} catch (Exception e) {
			String errorMessage = "An exception occurred during an attempt to compare the OCSP binaries with a reference: {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
		}
		return false;
	}

	private boolean matchByKeyHash(ResponderID tokenResponderId, ResponderId refResponderId) {
		return refResponderId.getSki() != null && Arrays.equals(refResponderId.getSki(), tokenResponderId.getKeyHash());
	}

	private boolean matchByName(ResponderID tokenResponderId, ResponderId refResponderId) {
		return refResponderId.getX500Principal() != null && tokenResponderId.getName() != null
				&& refResponderId.getX500Principal().equals(DSSASN1Utils.toX500Principal(tokenResponderId.getName()));
	}

}
