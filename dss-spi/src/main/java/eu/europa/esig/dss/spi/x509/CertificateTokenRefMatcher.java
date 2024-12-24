/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;

import java.util.Arrays;

/**
 * This class is used to verify if a given {@code CertificateToken} matches a {@code CertificateRef}
 *
 */
public class CertificateTokenRefMatcher {

	/**
	 * Default constructor
	 */
	public CertificateTokenRefMatcher() {
		// empty
	}

	/**
	 * This method verifies if the given {@code CertificateToken} matches the {@code CertificateRef}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param certificateRef {@link CertificateRef}
	 * @return TRUE if the reference corresponds to the certificate, FALSE otherwise
	 */
	public boolean match(CertificateToken certificateToken, CertificateRef certificateRef) {
		// If we only know the public key, the token is null
		if (certificateToken == null) {
			return false;
		}

		Digest certDigest = certificateRef.getCertDigest();
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		ResponderId responderId = certificateRef.getResponderId();
		if (certDigest != null && matchByDigest(certificateToken, certificateRef)) {
			return true;
		} else if (signerIdentifier != null && signerIdentifier.isRelatedToCertificate(certificateToken)) {
			return true;
		} else if (responderId != null && responderId.isRelatedToCertificate(certificateToken)) {
			return true;
		}
		return false;
	}

	/**
	 * This method verifies if only digest within the {@code certificateRef} corresponds to {@code certificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param certificateRef {@link CertificateRef}
	 * @return TRUE if the digest present within a reference match the one computed on certificate token's binaries
	 */
	public boolean matchByDigest(CertificateToken certificateToken, CertificateRef certificateRef) {
		Digest certDigest = certificateRef.getCertDigest();
		if (certDigest != null) {
			byte[] currentDigest = certificateToken.getDigest(certDigest.getAlgorithm());
			return Arrays.equals(currentDigest, certDigest.getValue());
		}
		return false;
	}

	/**
	 * This method verifies if only the serial number within the {@code certificateRef} corresponds
	 * to {@code certificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param certificateRef {@link CertificateRef}
	 * @return TRUE if the serial number present within a reference match the certificate token
	 */
	public boolean matchBySerialNumber(CertificateToken certificateToken, CertificateRef certificateRef) {
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		if (signerIdentifier != null && signerIdentifier.getSerialNumber() != null) {
			return certificateToken.getSerialNumber().equals(signerIdentifier.getSerialNumber());
		}
		return false;
	}

	/**
	 * This method verifies if only the issuer name within the {@code certificateRef} corresponds
	 * to {@code certificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param certificateRef {@link CertificateRef}
	 * @return TRUE if the issuer name present within a reference match the certificate token
	 */
	public boolean matchByIssuerName(CertificateToken certificateToken, CertificateRef certificateRef) {
		SignerIdentifier signerIdentifier = certificateRef.getCertificateIdentifier();
		if (signerIdentifier != null && signerIdentifier.getIssuerName() != null) {
			return DSSASN1Utils.x500PrincipalAreEquals(signerIdentifier.getIssuerName(), certificateToken.getIssuerX500Principal());
		}
		return false;
	}
	
	/**
	 * This method verifies if only the responder Id within the {@code certificateRef} corresponds
	 * to {@code certificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param certificateRef {@link CertificateRef}
	 * @return TRUE if the responder Id present within a reference match the certificate token
	 */
	public boolean matchByResponderId(CertificateToken certificateToken, CertificateRef certificateRef) {
		ResponderId responderId = certificateRef.getResponderId();
		if (responderId != null) {
			return responderId.isRelatedToCertificate(certificateToken);
		}
		return false;
	}

}
