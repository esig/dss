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
import eu.europa.esig.dss.alert.status.MessageStatus;
import eu.europa.esig.dss.enumerations.SigningOperation;
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

    /** The nature of the current operation the verification is done for */
    private SigningOperation signingOperation;

    /**
     * Default constructor to instantiate alerter
     *
     * @param validationContext {@link SignatureValidationContext}
     */
    public SignatureValidationAlerter(final SignatureValidationContext validationContext) {
        this.validationContext = validationContext;
    }

    /**
     * (Optional) Sets the current operation kind to provide a user-friendly error message
     *
     * @param signingOperation {@link SigningOperation}
     */
    public void setSigningOperation(SigningOperation signingOperation) {
        this.signingOperation = signingOperation;
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
            populateMessage(status);
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
            populateMessage(status);
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
            populateMessage(status);
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
            populateMessage(status);
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
            populateMessage(status);
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
            populateMessage(status);
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
            populateMessage(status);
            alertOnExpiredCertificate.alert(status);
        }
    }

    @Override
    public void assertCertificateNotExpired(CertificateToken certificateToken) {
        StatusAlert alertOnExpiredCertificate = validationContext.getCertificateVerifier().getAlertOnExpiredCertificate();
        if (alertOnExpiredCertificate == null) {
            LOG.trace("The verification of #assertCertificateNotExpired has been skipped. " +
                    "Please define CertificateVerifier#alertOnExpiredCertificate to execute validation.");
            return;
        }

        TokenStatus status = validationContext.certificateNotExpired(certificateToken);
        boolean success = status.isEmpty();
        if (!success) {
            populateMessage(status);
            alertOnExpiredCertificate.alert(status);
        }
    }

    @Override
    public void assertAllSignaturesAreYetValid() {
        StatusAlert alertOnNotYetValidCertificate = validationContext.getCertificateVerifier().getAlertOnNotYetValidCertificate();
        if (alertOnNotYetValidCertificate == null) {
            LOG.trace("The verification of #assertAllSignaturesAreYetValid has been skipped. " +
                    "Please define CertificateVerifier#alertOnNotYetValidCertificate to execute validation.");
            return;
        }

        SignatureStatus status = validationContext.allSignaturesAreYetValid();
        boolean success = status.isEmpty();
        if (!success) {
            populateMessage(status);
            alertOnNotYetValidCertificate.alert(status);
        }
    }

    @Override
    public void assertCertificateIsYetValid(CertificateToken certificateToken) {
        StatusAlert alertOnNotYetValidCertificate = validationContext.getCertificateVerifier().getAlertOnNotYetValidCertificate();
        if (alertOnNotYetValidCertificate == null) {
            LOG.trace("The verification of #assertCertificateIsYetValid has been skipped. " +
                    "Please define CertificateVerifier#alertOnNotYetValidCertificate to execute validation.");
            return;
        }

        TokenStatus status = validationContext.certificateIsYetValid(certificateToken);
        boolean success = status.isEmpty();
        if (!success) {
            populateMessage(status);
            alertOnNotYetValidCertificate.alert(status);
        }
    }

    /**
     * This method augments the validation message with the information about currently performing operation kind
     *
     * @param status {@link MessageStatus} to augment
     */
    protected void populateMessage(MessageStatus status) {
        if (status != null && signingOperation != null) {
            String originalMessage = status.getMessage();
            switch (signingOperation) {
                case SIGN:
                case COUNTER_SIGN:
                    status.setMessage(String.format("Error on signature creation : %s", originalMessage));
                    break;
                case EXTEND:
                    status.setMessage(String.format("Error on signature augmentation : %s", originalMessage));
                    break;
                case TIMESTAMP:
                    status.setMessage(String.format("Error on timestamp : %s", originalMessage));
                    break;
                case ADD_EVIDENCE_RECORD:
                    status.setMessage(String.format("Error on evidence record incorporation : %s", originalMessage));
                    break;
                case ADD_SIG_POLICY_STORE:
                    status.setMessage(String.format("Error on signature policy store incorporation : %s", originalMessage));
                    break;
                default:
                    throw new UnsupportedOperationException(String.format("The operation '%s' is not supported!", signingOperation));
            }
        }
    }

}
