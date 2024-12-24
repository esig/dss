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

import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.status.SignatureStatus;
import eu.europa.esig.dss.spi.validation.status.TokenStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class used {@code eu.europa.esig.dss.spi.validation.SignatureValidationContext} to perform validation and
 * executes alerts based on the validation result.
 * The configuration of the alerts and their behavior is defined within
 * {@code eu.europa.esig.dss.spi.validation.CertificateVerifier}.
 * If alert is not defined, the execution of the corresponding check is being skipped.
 *
 */
public class SignatureValidationAlerter implements ValidationAlerter {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationAlerter.class);

    /** SignatureValidationContext to perform the execution */
    private final SignatureValidationContext validationContext;

    /**
     * Default constructor to instantiate alerter
     *
     * @param validationContext {@link SignatureValidationContext}
     */
    public SignatureValidationAlerter(final SignatureValidationContext validationContext) {
        this.validationContext = validationContext;
    }

    @Override
    public void assertAllRequiredRevocationDataPresent() {
        StatusAlert alertOnMissingRevocationData = validationContext.getCertificateVerifier().getAlertOnMissingRevocationData();
        if (alertOnMissingRevocationData == null) {
            LOG.trace("The verification of #assertAllRequiredRevocationDataPresent has been skipped. " +
                    "Please define CertificateVerifier#alertOnMissingRevocationData to execute validation.");
            return;
        }

        TokenStatus status = validationContext.allRequiredRevocationDataPresent();
        boolean success = status.isEmpty();
        if (!success) {
            alertOnMissingRevocationData.alert(status);
        }
    }

    @Override
    public void assertAllPOECoveredByRevocationData() {
        StatusAlert alertOnUncoveredPOE = validationContext.getCertificateVerifier().getAlertOnUncoveredPOE();
        if (alertOnUncoveredPOE == null) {
            LOG.trace("The verification of #assertAllRequiredRevocationDataPresent has been skipped. " +
                    "Please define CertificateVerifier#alertOnUncoveredPOE to execute validation.");
            return;
        }

        TokenStatus status = validationContext.allPOECoveredByRevocationData();
        boolean success = status.isEmpty();
        if (!success) {
            alertOnUncoveredPOE.alert(status);
        }
    }

    @Override
    public void assertAllTimestampsValid() {
        StatusAlert alertOnInvalidTimestamp = validationContext.getCertificateVerifier().getAlertOnInvalidTimestamp();
        if (alertOnInvalidTimestamp == null) {
            LOG.trace("The verification of #assertAllTimestampsValid has been skipped. " +
                    "Please define CertificateVerifier#alertOnInvalidTimestamp to execute validation.");
            return;
        }

        TokenStatus status = validationContext.allTimestampsValid();
        boolean success = status.isEmpty();
        if (!success) {
            alertOnInvalidTimestamp.alert(status);
        }
    }

    @Override
    public void assertCertificateNotRevoked(CertificateToken certificateToken) {
        StatusAlert alertOnRevokedCertificate = validationContext.getCertificateVerifier().getAlertOnRevokedCertificate();
        if (alertOnRevokedCertificate == null) {
            LOG.trace("The verification of #assertCertificateNotRevoked has been skipped. " +
                    "Please define CertificateVerifier#alertOnRevokedCertificate to execute validation.");
            return;
        }

        TokenStatus status = validationContext.certificateNotRevoked(certificateToken);
        boolean success = status.isEmpty();
        if (!success) {
            alertOnRevokedCertificate.alert(status);
        }
    }

    @Override
    public void assertAllSignatureCertificatesNotRevoked() {
        StatusAlert alertOnRevokedCertificate = validationContext.getCertificateVerifier().getAlertOnRevokedCertificate();
        if (alertOnRevokedCertificate == null) {
            LOG.trace("The verification of #assertAllSignatureCertificatesNotRevoked has been skipped. " +
                    "Please define CertificateVerifier#alertOnRevokedCertificate to execute validation.");
            return;
        }

        TokenStatus status = validationContext.allSignatureCertificatesNotRevoked();
        boolean success = status.isEmpty();
        if (!success) {
            alertOnRevokedCertificate.alert(status);
        }
    }

    @Override
    public void assertAllSignatureCertificateHaveFreshRevocationData() {
        StatusAlert alertOnNoRevocationAfterBestSignatureTime = validationContext
                .getCertificateVerifier().getAlertOnNoRevocationAfterBestSignatureTime();
        if (alertOnNoRevocationAfterBestSignatureTime == null) {
            LOG.trace("The verification of #assertAllSignatureCertificateHaveFreshRevocationData has been skipped. " +
                    "Please define CertificateVerifier#alertOnNoRevocationAfterBestSignatureTime to execute validation.");
            return;
        }

        TokenStatus status = validationContext.allSignatureCertificateHaveFreshRevocationData();
        boolean success = status.isEmpty();
        if (!success) {
            alertOnNoRevocationAfterBestSignatureTime.alert(status);
        }
    }

    @Override
    public void assertAllSignaturesNotExpired() {
        StatusAlert alertOnExpiredCertificate = validationContext.getCertificateVerifier().getAlertOnExpiredCertificate();
        if (alertOnExpiredCertificate == null) {
            LOG.trace("The verification of #assertAllSignaturesNotExpired has been skipped. " +
                    "Please define CertificateVerifier#alertOnExpiredCertificate to execute validation.");
            return;
        }

        SignatureStatus status = validationContext.allSignaturesNotExpired();
        boolean success = status.isEmpty();
        if (!success) {
            alertOnExpiredCertificate.alert(status);
        }
    }

}
