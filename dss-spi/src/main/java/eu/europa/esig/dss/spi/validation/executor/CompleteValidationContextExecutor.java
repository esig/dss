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
package eu.europa.esig.dss.spi.validation.executor;

import eu.europa.esig.dss.spi.validation.SignatureValidationAlerter;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContext;

import java.util.Objects;

/**
 * This class executes complete validation of the {@code ValidationContext}, including running of all checks
 * with the alerts processing specified in CertificateVerifier
 *
 */
public class CompleteValidationContextExecutor implements ValidationContextExecutor {

    /** Singleton instance */
    public static final CompleteValidationContextExecutor INSTANCE = new CompleteValidationContextExecutor();

    /**
     * Default constructor
     */
    private CompleteValidationContextExecutor() {
        // empty
    }

    @Override
    public void validate(ValidationContext validationContext) {
        assertValidationContextSupported(validationContext);
        
        validationContext.validate();
        assertSignaturesValid(validationContext);
    }

    private void assertSignaturesValid(ValidationContext validationContext) {
        SignatureValidationAlerter validationAlerter = new SignatureValidationAlerter((SignatureValidationContext) validationContext);
        validationAlerter.assertAllTimestampsValid();
        validationAlerter.assertAllRequiredRevocationDataPresent();
        validationAlerter.assertAllPOECoveredByRevocationData();

        validationAlerter.assertAllSignaturesAreYetValid();
        validationAlerter.assertAllSignaturesNotExpired();
        validationAlerter.assertAllSignatureCertificatesNotRevoked();
        validationAlerter.assertAllSignatureCertificateHaveFreshRevocationData();
    }
    
    private static void assertValidationContextSupported(ValidationContext validationContext) {
        Objects.requireNonNull(validationContext, "ValidationContext cannot be null!");
        if (!(validationContext instanceof SignatureValidationContext)) {
            throw new UnsupportedOperationException("CompleteValidationContextExecutor supports only SignatureValidationContext class type!");
        }
    }

}
