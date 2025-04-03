package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningCertificateRefDigestAlgorithmCheck;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class builds a chain of validation checks for verification of the used digest algorithms
 * within the signing-certificate reference signed-attribute.
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class SigningCertificateRefDigestAlgorithmCheckChainBuilder<T extends XmlConstraintsConclusion> {

    /** The internationalization provider */
    private final I18nProvider i18nProvider;

    /** The conclusion result */
    private final T result;

    /** The token to be validated */
    private final TokenProxy token;

    /** Validation time */
    private final Date validationDate;

    /** Validation context */
    private final Context context;

    /** Validation policy */
    private final ValidationPolicy validationPolicy;

    /** The cryptographic information for the report */
    private XmlCryptographicValidation cryptographicValidation;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param validationDate {@link Date}
     * @param token {@link TokenProxy} to be validated
     * @param context {@link Context}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public SigningCertificateRefDigestAlgorithmCheckChainBuilder(
            final I18nProvider i18nProvider, final T result, final Date validationDate, final TokenProxy token,
            final Context context, final ValidationPolicy validationPolicy) {
        this.i18nProvider = i18nProvider;
        this.result = result;
        this.token = token;
        this.validationDate = validationDate;
        this.context = context;
        this.validationPolicy = validationPolicy;
    }

    /**
     * Executes validation of signing certificate references' digest algorithms against the cryptographic constraints
     *
     * @param chainItem returned by the validation process, to be continued with digest matcher checks
     * @return a list of {@link XmlCC}s containing validation results
     */
    public ChainItem<T> build(ChainItem<T> chainItem) {
        if (!token.isSigningCertificateReferencePresent()) {
            return chainItem;
        }

        List<CertificateRefWrapper> signingCertificateReferences = token.getSigningCertificateReferences();
        CertificateRefWrapper signingCertificateReference = token.getSigningCertificateReference();

        // This code ensures that at least one good digest algorithm is found for every defined signing certificate reference
        final Map<String, List<CertificateRefWrapper>> signCertRefsMap = new HashMap<>();
        signingCertificateReferences.forEach(r -> signCertRefsMap.computeIfAbsent(r.getCertificateId(), s -> new ArrayList<>()).add(r));
        for (String certificateId : signCertRefsMap.keySet()) {
            List<CertificateRefWrapper> certificateRefWrappers = signCertRefsMap.get(certificateId);

            SubContext subContext;
            if (signingCertificateReference != null && signingCertificateReference.getCertificateId().equals(certificateId)) {
                subContext = SubContext.SIGNING_CERT;
            } else {
                subContext = SubContext.CA_CERTIFICATE;
            }

            SigningCertificateRefDigestAlgorithmCheck<T> signCertCheck =
                    signingCertificateRefDigestAlgoCheckResult(certificateRefWrappers, certificateId, subContext);

            if (chainItem == null) {
                chainItem = signCertCheck;
            } else {
                chainItem = chainItem.setNextItem(signCertCheck);
            }

            XmlCC cryptoValidationResult = signCertCheck.getCryptographicValidationResult();
            if (cryptographicValidation == null || (cryptographicValidation.isSecure() && !isValid(cryptoValidationResult))) {
                cryptographicValidation = buildCryptographicValidation(cryptoValidationResult, certificateId);
            }
        }

        return chainItem;
    }

    private SigningCertificateRefDigestAlgorithmCheck<T> signingCertificateRefDigestAlgoCheckResult(
            List<CertificateRefWrapper> signCertRefs, String certificateId, SubContext subContext) {
        LevelRule constraint = validationPolicy.getSigningCertificateDigestAlgorithmConstraint(context);
        return new SigningCertificateRefDigestAlgorithmCheck<>(i18nProvider, result, validationDate,
                signCertRefs, certificateId, context, subContext, validationPolicy, constraint);
    }

    /**
     * Gets the result of cryptographic validation.
     * NOTE: Shall be called after {@code #build} method.
     *
     * @return {@link XmlCryptographicValidation}
     */
    public XmlCryptographicValidation getCryptographicValidation() {
        return cryptographicValidation;
    }

    private XmlCryptographicValidation buildCryptographicValidation(XmlCC ccResult, String certificateId) {
        XmlCryptographicValidation xmlCryptographicValidation = new XmlCryptographicValidation();
        xmlCryptographicValidation.setAlgorithm(ccResult.getVerifiedAlgorithm());
        xmlCryptographicValidation.setNotAfter(ccResult.getNotAfter());
        xmlCryptographicValidation.setSecure(isValid(ccResult));
        xmlCryptographicValidation.setValidationTime(validationDate);
        xmlCryptographicValidation.setConcernedMaterial(getTokenDescription(certificateId));
        return xmlCryptographicValidation;
    }

    private boolean isValid(XmlCC xmlConclusion) {
        return xmlConclusion != null && xmlConclusion.getConclusion() != null
                && Indication.PASSED == xmlConclusion.getConclusion().getIndication();
    }

    private String getTokenDescription(String id) {
        return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_ID, MessageTag.ACCM_POS_SIG_CERT_REF, id);
    }

}
