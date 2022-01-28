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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureValidationContext;

import java.util.Date;
import java.util.List;

/**
 * This class is used to verify if the signature can be created according to the provided requirements
 * in a signature parameters instance
 *
 */
public class SignatureRequirementsChecker {

    /** CertificateVerifier to be used for certificates validation */
    private final CertificateVerifier certificateVerifier;

    /** The signature parameters used for signature creation/extension */
    private final AbstractSignatureParameters<?> signatureParameters;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param signatureParameters {@link AbstractSignatureParameters}
     */
    public SignatureRequirementsChecker(final CertificateVerifier certificateVerifier,
                                        final AbstractSignatureParameters<?> signatureParameters) {
        this.certificateVerifier = certificateVerifier;
        this.signatureParameters = signatureParameters;
    }

    /**
     * This method verifies whether the provided certificate token is acceptable for a signature creation
     * against the provided {@code signatureParameters}
     *
     * @param certificateToken {@link CertificateToken}
     */
    public void assertSigningCertificateIsValid(final CertificateToken certificateToken) {
        assertSigningCertificateIsYetValid(certificateToken);
        assertSigningCertificateIsNotExpired(certificateToken);
        assertCertificatesAreNotRevoked(certificateToken);
    }

    /**
     * This method verifies a signing certificate of the given {@code signature}
     *
     * @param signature {@link AdvancedSignature} to verify
     */
    public void assertSigningCertificateIsValid(final AdvancedSignature signature) {
        CertificateToken signingCertificate = signature.getSigningCertificateToken(); // can be null
        assertSigningCertificateIsYetValid(signingCertificate);
        assertSigningCertificateIsNotExpired(signingCertificate);
        assertCertificatesAreNotRevoked(signature);
    }

    /**
     * This method verifies whether the given {@code CertificateToken} is yet valid at the current time
     *
     * @param certificateToken {@link CertificateToken}
     * @return TRUE if the certificate is yet valid, FALSE otherwise
     */
    private void assertSigningCertificateIsYetValid(final CertificateToken certificateToken) {
        if (signatureParameters.isSignWithNotYetValidCertificate()) {
            return;
        }

        if (certificateToken == null) {
            throw new IllegalInputException("Signing certificate token was not found! Unable to verify its validity range. " +
                    "Use method setSignWithNotYetValidCertificate(true) to skip the check.");
        }

        final Date notBefore = certificateToken.getNotBefore();
        final Date notAfter = certificateToken.getNotAfter();
        final Date signingDate = signatureParameters.bLevel().getSigningDate();
        if (signingDate.before(notBefore)) {
            throw new IllegalArgumentException(String.format("The signing certificate (notBefore : %s, notAfter : %s) " +
                            "is not yet valid at signing time %s! Change signing certificate or use method " +
                            "setSignWithNotYetValidCertificate(true).",
                    notBefore.toString(), notAfter.toString(), signingDate.toString()));
        }
    }

    /**
     * This method verifies whether the given {@code CertificateToken} is not expired at the current time
     *
     * @param certificateToken {@link CertificateToken}
     * @return TRUE if the certificate is not expired, FALSE otherwise
     */
    private void assertSigningCertificateIsNotExpired(final CertificateToken certificateToken) {
        if (signatureParameters.isSignWithExpiredCertificate()) {
            return;
        }

        if (certificateToken == null) {
            throw new IllegalInputException("Signing certificate token was not found! Unable to verify its validity range. " +
                    "Use method setSignWithExpiredCertificate(true) to skip the check.");
        }

        final Date notBefore = certificateToken.getNotBefore();
        final Date notAfter = certificateToken.getNotAfter();
        final Date signingDate = signatureParameters.bLevel().getSigningDate();
        if (signingDate.after(notAfter)) {
            throw new IllegalArgumentException(String.format("The signing certificate (notBefore : %s, notAfter : %s) " +
                            "is expired at signing time %s! Change signing certificate or use method " +
                            "setSignWithExpiredCertificate(true).",
                    notBefore.toString(), notAfter.toString(), signingDate.toString()));
        }
    }

    /**
     * This method verifies whether the given {@code CertificateToken} is not revoked nor suspended at the current time
     *
     * @param certificateToken {@link CertificateToken}
     * @return TRUE if the certificate is not expired, FALSE otherwise
     */
    private void assertCertificatesAreNotRevoked(final CertificateToken certificateToken) {
        if (!signatureParameters.isCheckCertificateRevocation()) {
            return;
        }

        final SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(certificateVerifier);
        validationContext.setCurrentTime(signatureParameters.bLevel().getSigningDate());

        final List<CertificateToken> certificateChain = signatureParameters.getCertificateChain();
        if (Utils.isCollectionEmpty(certificateChain)) {
            throw new NullPointerException("Certificate chain shall be provided for a revocation check! " +
                    "Please use parameters.setCertificateChain(...) method to provide a certificate chain.");
        }
        validationContext.addCertificateTokenForVerification(certificateToken);
        for (CertificateToken certificate : certificateChain) {
            validationContext.addCertificateTokenForVerification(certificate);
        }
        validationContext.validate();

        validationContext.checkAllRequiredRevocationDataPresent();
        validationContext.checkAllCertificatesValid();
    }

    /**
     * This method verifies whether the given {@code AdvancedSignature} do not contain revoked certificates
     *
     * @param signature {@link AdvancedSignature}
     * @return TRUE if the certificate is not expired, FALSE otherwise
     */
    private void assertCertificatesAreNotRevoked(final AdvancedSignature signature) {
        if (!signatureParameters.isCheckCertificateRevocation()) {
            return;
        }

        final SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(certificateVerifier);
        validationContext.setCurrentTime(signatureParameters.bLevel().getSigningDate());

        validationContext.addSignatureForVerification(signature);

        validationContext.validate();

        validationContext.checkAllRequiredRevocationDataPresent();
        validationContext.checkAllCertificatesValid();
    }

}
