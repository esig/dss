package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

/**
 * Checks conformance of a signature to the requested baseline format
 *
 * @param <AS> {@code DefaultAdvancedSignature}
 *
 */
public abstract class BaselineRequirementsChecker<AS extends DefaultAdvancedSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(BaselineRequirementsChecker.class);

    /** The signature object */
    protected final AS signature;

    /**
     * The offline copy of a CertificateVerifier
     */
    private final CertificateVerifier offlineCertificateVerifier;

    /**
     * Default constructor
     *
     * @param signature {@link DefaultAdvancedSignature} to validate
     * @param offlineCertificateVerifier {@link CertificateVerifier} offline copy of a used CertificateVerifier
     */
    public BaselineRequirementsChecker(final AS signature, final CertificateVerifier offlineCertificateVerifier) {
        this.signature = signature;
        this.offlineCertificateVerifier = offlineCertificateVerifier;
    }

    /**
     * Checks if the signature has a corresponding BASELINE-B profile
     *
     * @return TRUE if the signature has a BASELINE-B profile, FALSE otherwise
     */
    public abstract boolean hasBaselineBProfile();

    /**
     * Checks if the signature has a corresponding BASELINE-T profile
     *
     * @return TRUE if the signature has a BASELINE-T profile, FALSE otherwise
     */
    public boolean hasBaselineTProfile() {
        // SignatureTimeStamp (Cardinality >= 1)
        if (Utils.isCollectionEmpty(signature.getSignatureTimestamps())) {
            LOG.trace("SignatureTimeStamp shall be present for BASELINE-T signature (cardinality >= 1)!");
            return false;
        }
        CertificateToken signingCertificate = signature.getSigningCertificateToken();
        if (signingCertificate != null) {
            for (TimestampToken timestampToken : signature.getSignatureTimestamps()) {
                if (!timestampToken.getCreationDate().before(signingCertificate.getNotAfter())) {
                    LOG.warn("SignatureTimeStamp shall be generated before the signing certificate expiration for BASELINE-B signature!");
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Checks if the signature has a corresponding BASELINE-LT profile
     *
     * @return TRUE if the signature has a BASELINE-LT profile, FALSE otherwise
     */
    public boolean hasBaselineLTProfile() {
        Objects.requireNonNull(offlineCertificateVerifier, "offlineCertificateVerifier cannot be null!");

        ListCertificateSource certificateSources = getCertificateSourcesExceptLastArchiveTimestamp();
        boolean certificateFound = certificateSources.getNumberOfCertificates() > 0;
        boolean allSelfSigned = certificateFound && certificateSources.isAllSelfSigned();

        boolean emptyCRLs = signature.getCompleteCRLSource().getAllRevocationBinaries().isEmpty();
        boolean emptyOCSPs = signature.getCompleteOCSPSource().getAllRevocationBinaries().isEmpty();
        boolean emptyRevocation = emptyCRLs && emptyOCSPs;

        boolean minimalLTRequirement = !allSelfSigned && !emptyRevocation;
        if (minimalLTRequirement) {
            // check presence of all revocation data
            return isAllRevocationDataPresent(certificateSources, offlineCertificateVerifier);
        }
        return minimalLTRequirement;
    }

    /**
     * Returns a list of certificate sources with an exception of the last archive timestamp if available
     *
     * @return {@link ListCertificateSource}
     */
    protected ListCertificateSource getCertificateSourcesExceptLastArchiveTimestamp() {
        ListCertificateSource certificateSource = new ListCertificateSource(signature.getCertificateSource());
        certificateSource.addAll(signature.getTimestampSource().getTimestampCertificateSourcesExceptLastArchiveTimestamp());
        certificateSource.addAll(signature.getCounterSignaturesCertificateSource());
        return certificateSource;
    }

    private boolean isAllRevocationDataPresent(ListCertificateSource certificateSources,
                                               CertificateVerifier offlineCertificateVerifier) {
        SignatureValidationContext validationContext = new SignatureValidationContext();
        offlineCertificateVerifier.setSignatureCRLSource(signature.getCompleteCRLSource());
        offlineCertificateVerifier.setSignatureOCSPSource(signature.getCompleteOCSPSource());
        offlineCertificateVerifier.setSignatureCertificateSource(signature.getCompleteCertificateSource());
        validationContext.initialize(offlineCertificateVerifier);

        List<CertificateValidity> certificateValidityList = signature.getCandidatesForSigningCertificate()
                .getCertificateValidityList();
        for (CertificateValidity certificateValidity : certificateValidityList) {
            if (certificateValidity.isValid() && certificateValidity.getCertificateToken() != null) {
                validationContext.addCertificateTokenForVerification(certificateValidity.getCertificateToken());
            }
        }

        for (final CertificateToken certificate : certificateSources.getAllCertificateTokens()) {
            validationContext.addCertificateTokenForVerification(certificate);
        }
        validationContext.validate();
        return validationContext.checkAllRequiredRevocationDataPresent();
    }

    /**
     * Checks if the signature has a corresponding BASELINE-LTA profile
     *
     * @return TRUE if the signature has a BASELINE-LTA profile, FALSE otherwise
     */
    public boolean hasBaselineLTAProfile() {
        if (Utils.isCollectionEmpty(signature.getArchiveTimestamps())) {
            LOG.trace("ArchiveTimeStamp shall be present for BASELINE-LTA signature (cardinality >= 1)!");
            return false;
        }
        return true;
    }

}
