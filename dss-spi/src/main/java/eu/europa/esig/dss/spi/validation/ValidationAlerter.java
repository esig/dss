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
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This class used {@code eu.europa.esig.dss.spi.validation.ValidationContext} to perform validation and
 * executes alerts based on the validation result.
 */
public interface ValidationAlerter {

    /**
     * This method verifies if all processed certificates have a revocation data.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnMissingRevocationData(eu.europa.esig.dss.alert.StatusAlert)}
     */
    void assertAllRequiredRevocationDataPresent();

    /**
     * This method verifies if all POE (timestamp tokens) are covered by a revocation data.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnUncoveredPOE(eu.europa.esig.dss.alert.StatusAlert)}
     */
    void assertAllPOECoveredByRevocationData();

    /**
     * This method verifies if all processed timestamps are valid and intact.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnInvalidTimestamp(eu.europa.esig.dss.alert.StatusAlert)}
     */
    void assertAllTimestampsValid();

    /**
     * This method verifies if the certificate is not revoked.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnRevokedCertificate(eu.europa.esig.dss.alert.StatusAlert)}
     *
     * @param certificateToken {@code CertificateToken} certificate to be checked
     */
    void assertCertificateNotRevoked(CertificateToken certificateToken);

    /**
     * This method verifies recursively whether none of the signature's certificate chain certificates are revoked.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnRevokedCertificate(eu.europa.esig.dss.alert.StatusAlert)}
     */
    void assertAllSignatureCertificatesNotRevoked();

    /**
     * This method verifies whether for all signature's certificate chain certificates there is a fresh revocation data,
     * after the earliest available timestamp token production time.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnNoRevocationAfterBestSignatureTime(eu.europa.esig.dss.alert.StatusAlert)}
     */
    void assertAllSignatureCertificateHaveFreshRevocationData();

    /**
     * This method verifies whether all signatures added to the ValidationContext are not yet expired.
     * The behavior of the method is configured with
     * {@link CertificateVerifier#setAlertOnExpiredCertificate(eu.europa.esig.dss.alert.StatusAlert)}
     */
    void assertAllSignaturesNotExpired();

}
