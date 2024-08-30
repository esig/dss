package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.spi.validation.TrustAnchorVerifier;

/**
 * This class loads {@code TrustAnchorVerifier} from a provided {@code eu.europa.esig.dss.policy.ValidationPolicy}
 *
 */
public class TrustAnchorVerifierFactory {

    /** Validation policy to load TrustAnchorVerifier from */
    private final ValidationPolicy validationPolicy;

    /**
     * Default constructor
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    public TrustAnchorVerifierFactory(final ValidationPolicy validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    /**
     * Creates the {@code TrustAnchorVerifier}
     *
     * @return {@link TrustAnchorVerifier}
     */
    public TrustAnchorVerifier create() {
        final TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createEmptyTrustAnchorVerifier();
        instantiateAcceptUntrustedCertificateChains(trustAnchorVerifier, validationPolicy);
        instantiateUseSunsetDate(trustAnchorVerifier, validationPolicy);
        return trustAnchorVerifier;
    }

    private void instantiateAcceptUntrustedCertificateChains(TrustAnchorVerifier trustAnchorVerifier,
                                                             ValidationPolicy validationPolicy) {
        if (validationPolicy.getRevocationConstraints() != null) {
            boolean acceptUntrustedCertificateChains = getAcceptUntrustedCertificateChains(
                    validationPolicy.getRevocationConstraints().getBasicSignatureConstraints());
            trustAnchorVerifier.setAcceptRevocationUntrustedCertificateChains(acceptUntrustedCertificateChains);
        }
        if (validationPolicy.getTimestampConstraints() != null) {
            boolean acceptUntrustedCertificateChains = getAcceptUntrustedCertificateChains(
                    validationPolicy.getTimestampConstraints().getBasicSignatureConstraints());
            trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(acceptUntrustedCertificateChains);
        }
    }

    private boolean getAcceptUntrustedCertificateChains(BasicSignatureConstraints basicSignatureConstraints) {
        if (basicSignatureConstraints != null) {
            LevelConstraint constraint = basicSignatureConstraints.getProspectiveCertificateChain();
            return constraint == null || !Level.FAIL.equals(constraint.getLevel());
        }
        return true;
    }

    private void instantiateUseSunsetDate(TrustAnchorVerifier trustAnchorVerifier, ValidationPolicy validationPolicy) {
        boolean useSunsetDate = false;
        if (validationPolicy.getSignatureConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getSignatureConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getCounterSignatureConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getTimestampConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getTimestampConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getRevocationConstraints() != null) {
            useSunsetDate = useSunsetDate || getUseSunsetDate(validationPolicy.getRevocationConstraints().getBasicSignatureConstraints());
        }
        trustAnchorVerifier.setUseSunsetDate(useSunsetDate);
    }

    private boolean getUseSunsetDate(BasicSignatureConstraints basicSignatureConstraints) {
        if (basicSignatureConstraints != null) {
            if (basicSignatureConstraints.getSigningCertificate() != null) {
                LevelConstraint constraint = basicSignatureConstraints.getSigningCertificate().getSunsetDate();
                if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
                    return true;
                }
            }
            if (basicSignatureConstraints.getCACertificate() != null) {
                LevelConstraint constraint = basicSignatureConstraints.getCACertificate().getSunsetDate();
                if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
                    return true;
                }
            }
        }
        return false;
    }

}
