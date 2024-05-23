package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.policy.RuleUtils;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.spi.validation.RevocationDataVerifier;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class loads {@code RevocationDataVerifier} from a provided {@code eu.europa.esig.dss.policy.ValidationPolicy}
 *
 */
public class RevocationDataVerifierFactory {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationDataVerifier.class);

    /** Validation policy to load RevocationDataVerifier from */
    private final ValidationPolicy validationPolicy;

    /** The used validation time */
    private Date validationTime;

    /**
     * Default constructor
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    public RevocationDataVerifierFactory(final ValidationPolicy validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    /**
     * Gets validation time. Instantiates value to the current time, if not provided explicitly.
     *
     * @return {@link Date}
     */
    protected Date getValidationTime() {
        if (validationTime == null) {
            validationTime = new Date();
        }
        return validationTime;
    }

    /**
     * Sets the used validation time
     *
     * @param validationTime {@link Date}
     * @return this {@code RevocationDataVerifierFactory}
     */
    public RevocationDataVerifierFactory setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
        return this;
    }

    /**
     * Creates the {@code RevocationDataVerifier}
     *
     * @return {@link RevocationDataVerifier}
     */
    public RevocationDataVerifier create() {
        final RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createEmptyRevocationDataVerifier();
        instantiateCryptographicConstraints(revocationDataVerifier, validationPolicy);
        instantiateRevocationSkipConstraints(revocationDataVerifier, validationPolicy);
        instantiateRevocationFreshnessConstraints(revocationDataVerifier, validationPolicy);
        return revocationDataVerifier;
    }

    private void instantiateCryptographicConstraints(final RevocationDataVerifier revocationDataVerifier,
                                                     ValidationPolicy validationPolicy) {
        List<DigestAlgorithm> acceptableDigestAlgorithms;
        Map<EncryptionAlgorithm, Integer> acceptableEncryptionAlgorithms;

        final CryptographicConstraintWrapper constraint = getRevocationCryptographicConstraints(validationPolicy);
        if (constraint != null && Level.FAIL.equals(constraint.getLevel())) {
            Date currentTime = getValidationTime();
            acceptableDigestAlgorithms = constraint.getReliableDigestAlgorithmsAtTime(currentTime);
            acceptableEncryptionAlgorithms = constraint.getReliableEncryptionAlgorithmsWithMinimalKeyLengthAtTime(currentTime);
        } else {
            LOG.info("No enforced cryptographic constraints have been found in the provided validation policy. Accept all cryptographic algorithms.");
            acceptableDigestAlgorithms = Arrays.asList(DigestAlgorithm.values());
            acceptableEncryptionAlgorithms = new EnumMap<>(EncryptionAlgorithm.class);
            for (EncryptionAlgorithm encryptionAlgorithm : EncryptionAlgorithm.values()) {
                acceptableEncryptionAlgorithms.put(encryptionAlgorithm, 0);
            }
        }
        revocationDataVerifier.setAcceptableDigestAlgorithms(acceptableDigestAlgorithms);
        revocationDataVerifier.setAcceptableEncryptionAlgorithmKeyLength(acceptableEncryptionAlgorithms);
    }

    private CryptographicConstraintWrapper getRevocationCryptographicConstraints(ValidationPolicy validationPolicy) {
        final CryptographicConstraint cryptographicConstraint = validationPolicy.getSignatureCryptographicConstraint(Context.REVOCATION);
        return cryptographicConstraint != null ? new CryptographicConstraintWrapper(cryptographicConstraint) : null;
    }

    private void instantiateRevocationSkipConstraints(final RevocationDataVerifier revocationDataVerifier,
                                                             ValidationPolicy validationPolicy) {
        final Set<String> certificateExtensions = new HashSet<>();
        final Set<String> certificatePolicies = new HashSet<>();

        if (validationPolicy.getSignatureConstraints() != null) {
            populateRevocationSkipFromBasicSignatureConstraints(certificateExtensions, certificatePolicies,
                    validationPolicy.getSignatureConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getCounterSignatureConstraints() != null) {
            populateRevocationSkipFromBasicSignatureConstraints(certificateExtensions, certificatePolicies,
                    validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getRevocationConstraints() != null) {
            populateRevocationSkipFromBasicSignatureConstraints(certificateExtensions, certificatePolicies,
                    validationPolicy.getRevocationConstraints().getBasicSignatureConstraints());
        }
        if (validationPolicy.getTimestampConstraints() != null) {
            populateRevocationSkipFromBasicSignatureConstraints(certificateExtensions, certificatePolicies,
                    validationPolicy.getTimestampConstraints().getBasicSignatureConstraints());
        }

        // TODO : remove in DSS 6.2
        ensureOcspNoCheck(certificateExtensions, validationPolicy);

        revocationDataVerifier.setRevocationSkipCertificateExtensions(certificateExtensions);
        revocationDataVerifier.setRevocationSkipCertificatePolicies(certificatePolicies);
    }

    /**
     * This is a temporary method since DSS 6.1 to ensure smooth migration to a new version of DSS 6.2.
     * Adds ocsp-no-check extension to a list of certificate extensions for a revocation data check skip,
     * when not present in the policy.
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    private void ensureOcspNoCheck(final Set<String> certificateExtensions, ValidationPolicy validationPolicy) {
        RevocationConstraints revocationConstraints = validationPolicy.getRevocationConstraints();
        if (revocationConstraints != null) {
            BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
            if (basicSignatureConstraints != null) {
                CertificateConstraints signingCertificate = basicSignatureConstraints.getSigningCertificate();
                if (signingCertificate != null && signingCertificate.getRevocationDataSkip() != null) {
                    // RevocationData skip check is defined
                    return;
                }
            }
        }
        LOG.info("No RevocationDataSkip constraint is defined in the validation policy for Revocation/SigningCertificate element! " +
                "Default behavior with ocsp-no-check is added to processing. Please set the constraint explicitly. To be required since DSS 6.2.");
        certificateExtensions.add(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
    }

    private void populateRevocationSkipFromBasicSignatureConstraints(
            final Set<String> certificateExtensions, final Set<String> certificatePolicies,
            BasicSignatureConstraints basicSignatureConstraints) {
        if (basicSignatureConstraints != null) {
            populateRevocationSkipFromCertificateConstraints(certificateExtensions, certificatePolicies,
                    basicSignatureConstraints.getSigningCertificate());
            populateRevocationSkipFromCertificateConstraints(certificateExtensions, certificatePolicies,
                    basicSignatureConstraints.getCACertificate());
        }
    }

    private void populateRevocationSkipFromCertificateConstraints(
            final Set<String> certificateExtensions, final Set<String> certificatePolicies,
            CertificateConstraints certificateConstraints) {
        if (certificateConstraints == null) {
            return;
        }
        CertificateValuesConstraint revocationDataSkipConstraint = certificateConstraints.getRevocationDataSkip();
        if (revocationDataSkipConstraint == null) {
            return;
        }

        MultiValuesConstraint certificateExtensionsConstraint = revocationDataSkipConstraint.getCertificateExtensions();
        if (certificateExtensionsConstraint != null) {
            certificateExtensions.addAll(certificateExtensionsConstraint.getId());
        }

        MultiValuesConstraint certificatePoliciesConstraint = revocationDataSkipConstraint.getCertificatePolicies();
        if (certificatePoliciesConstraint != null) {
            certificatePolicies.addAll(certificatePoliciesConstraint.getId());
        }
    }

    private void instantiateRevocationFreshnessConstraints(final RevocationDataVerifier revocationDataVerifier,
                                                                  ValidationPolicy validationPolicy) {
        boolean revocationFreshnessNextUpdateConstraint = false;
        if (validationPolicy.getSignatureConstraints() != null || validationPolicy.getCounterSignatureConstraints() != null) {
            revocationDataVerifier.setSignatureMaximumRevocationFreshness(getSignatureRevocationFreshnessConstraint(validationPolicy));
            if (validationPolicy.getSignatureConstraints() != null) {
                revocationFreshnessNextUpdateConstraint = getRevocationFreshnessNextUpdateConstraint(
                        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints());
            }
            if (!revocationFreshnessNextUpdateConstraint && validationPolicy.getCounterSignatureConstraints() != null) {
                revocationFreshnessNextUpdateConstraint = getRevocationFreshnessNextUpdateConstraint(
                        validationPolicy.getCounterSignatureConstraints().getBasicSignatureConstraints());
            }
        }
        if (validationPolicy.getTimestampConstraints() != null) {
            BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
            revocationDataVerifier.setTimestampMaximumRevocationFreshness(getRevocationFreshnessConstraint(basicSignatureConstraints));
            if (!revocationFreshnessNextUpdateConstraint && validationPolicy.getTimestampConstraints() != null) {
                revocationFreshnessNextUpdateConstraint = getRevocationFreshnessNextUpdateConstraint(
                        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints());
            }
        }
        if (validationPolicy.getRevocationConstraints() != null) {
            BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getRevocationConstraints().getBasicSignatureConstraints();
            revocationDataVerifier.setRevocationMaximumRevocationFreshness(getRevocationFreshnessConstraint(basicSignatureConstraints));
            if (!revocationFreshnessNextUpdateConstraint && validationPolicy.getRevocationConstraints() != null) {
                revocationFreshnessNextUpdateConstraint = getRevocationFreshnessNextUpdateConstraint(
                        validationPolicy.getRevocationConstraints().getBasicSignatureConstraints());
            }
        }
        revocationDataVerifier.setCheckRevocationFreshnessNextUpdate(revocationFreshnessNextUpdateConstraint);
    }

    private Long getSignatureRevocationFreshnessConstraint(ValidationPolicy validationPolicy) {
        Long maximumRevocationFreshness = null;

        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        if (signatureConstraints != null) {
            maximumRevocationFreshness = getRevocationFreshnessConstraint(signatureConstraints.getBasicSignatureConstraints());
        }
        SignatureConstraints counterSignatureConstraints = validationPolicy.getCounterSignatureConstraints();
        if (counterSignatureConstraints != null) {
            Long counterSignatureRevocationFreshnessConstraint = getRevocationFreshnessConstraint(counterSignatureConstraints.getBasicSignatureConstraints());
            if (maximumRevocationFreshness == null || (counterSignatureRevocationFreshnessConstraint != null
                    && counterSignatureRevocationFreshnessConstraint < maximumRevocationFreshness)) {
                maximumRevocationFreshness = counterSignatureRevocationFreshnessConstraint;
            }
        }

        return maximumRevocationFreshness;
    }

    private Long getRevocationFreshnessConstraint(BasicSignatureConstraints basicSignatureConstraints) {
        Long maximumRevocationFreshness = null;
        if (basicSignatureConstraints != null) {
            CertificateConstraints signingCertificateConstraints = basicSignatureConstraints.getSigningCertificate();
            if (signingCertificateConstraints != null) {
                maximumRevocationFreshness = getRevocationFreshnessConstraintValue(signingCertificateConstraints);
            }
            CertificateConstraints caCertificateConstraints = basicSignatureConstraints.getCACertificate();
            if (caCertificateConstraints != null) {
                Long caCertRevocationFreshness = getRevocationFreshnessConstraintValue(caCertificateConstraints);
                if (maximumRevocationFreshness == null || (caCertRevocationFreshness != null && caCertRevocationFreshness < maximumRevocationFreshness)) {
                    maximumRevocationFreshness = caCertRevocationFreshness;
                }
            }
        }
        return maximumRevocationFreshness;
    }

    private Long getRevocationFreshnessConstraintValue(CertificateConstraints certificateConstraints) {
        TimeConstraint revocationFreshness = certificateConstraints.getRevocationFreshness();
        if (revocationFreshness != null) {
            return RuleUtils.convertDuration(revocationFreshness);
        }
        return null;
    }

    private boolean getRevocationFreshnessNextUpdateConstraint(BasicSignatureConstraints basicSignatureConstraints) {
        if (basicSignatureConstraints != null) {
            CertificateConstraints signingCertificateConstraint = basicSignatureConstraints.getSigningCertificate();
            if (signingCertificateConstraint != null && signingCertificateConstraint.getRevocationFreshnessNextUpdate() != null) {
                return true;
            }
            CertificateConstraints caCertificateConstraint = basicSignatureConstraints.getCACertificate();
            if (caCertificateConstraint != null && caCertificateConstraint.getRevocationFreshnessNextUpdate() != null) {
                return true;
            }
        }
        return false;
    }

}
