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
package eu.europa.esig.dss.spi.x509;

import java.util.Arrays;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;

public class CertificateTokenRefMatcher {

	public boolean match(CertificateToken certificateToken, CertificateRef certificateRef) {
		// If we only know the public key, the token is null
		if (certificateToken == null) {
			return false;
		}

		Digest certDigest = certificateRef.getCertDigest();
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		ResponderId responderId = certificateRef.getResponderId();
		if (certDigest != null) {
			return matchByDigest(certificateToken, certificateRef);
		} else if (signerIdentifier != null && signerIdentifier.isRelatedToCertificate(certificateToken)) {
			return true;
		} else if (responderId != null && responderId.isRelatedToCertificate(certificateToken)) {
			return true;
		}
		return false;
	}

	public boolean matchByDigest(CertificateToken certificateToken, CertificateRef certificateRef) {
		Digest certDigest = certificateRef.getCertDigest();
		if (certDigest != null) {
			byte[] currentDigest = certificateToken.getDigest(certDigest.getAlgorithm());
			return Arrays.equals(currentDigest, certDigest.getValue());
		}
		return false;
	}

	public boolean matchBySerialNumber(CertificateToken certificateToken, CertificateRef certificateRef) {
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		if (signerIdentifier != null && signerIdentifier.getSerialNumber() != null) {
			return certificateToken.getSerialNumber().equals(signerIdentifier.getSerialNumber());
		}
		return false;
	}

	public boolean matchByIssuerName(CertificateToken certificateToken, CertificateRef certificateRef) {
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		if (signerIdentifier != null && signerIdentifier.getIssuerName() != null) {
			return DSSASN1Utils.x500PrincipalAreEquals(signerIdentifier.getIssuerName(), certificateToken.getIssuerX500Principal());
		}
		return false;
	}
	
	public boolean matchByResponderId(CertificateToken certificateToken, CertificateRef certificateRef) {
		ResponderId responderId = certificateRef.getResponderId();
		if (responderId != null) {
			return responderId.isRelatedToCertificate(certificateToken);
		}
		return false;
	}

}
