package eu.europa.esig.dss.validation.executor.context;

import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContextExecutor;

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
        Objects.requireNonNull(validationContext, "ValidationContext cannot be null!");
        validationContext.validate();
        assertSignaturesValid(validationContext);
    }

    private void assertSignaturesValid(ValidationContext validationContext) {
        validationContext.checkAllTimestampsValid();
        validationContext.checkAllRequiredRevocationDataPresent();
        validationContext.checkAllPOECoveredByRevocationData();

        validationContext.checkAllSignaturesNotExpired();
        validationContext.checkAllSignatureCertificatesNotRevoked();
        validationContext.checkAllSignatureCertificateHaveFreshRevocationData();
    }

}
