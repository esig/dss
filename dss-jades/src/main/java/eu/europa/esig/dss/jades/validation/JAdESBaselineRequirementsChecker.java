package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.validation.BaselineRequirementsChecker;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Performs checks according to EN 119 182-1 v1.1.1
 * "6.3 Requirements on JAdES components and services"
 *
 */
public class JAdESBaselineRequirementsChecker extends BaselineRequirementsChecker<JAdESSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(JAdESBaselineRequirementsChecker.class);

    /**
     * Default constructor
     *
     * @param signature                  {@link JAdESSignature} to validate
     * @param offlineCertificateVerifier {@link CertificateVerifier} offline copy of a used CertificateVerifier
     */
    public JAdESBaselineRequirementsChecker(JAdESSignature signature, CertificateVerifier offlineCertificateVerifier) {
        super(signature, offlineCertificateVerifier);
    }

    @Override
    public boolean hasBaselineBProfile() {
        JWS jws = signature.getJws();
        Headers headers = jws.getHeaders();
        JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
        // alg (Cardinality == 1)
        if (headers.getObjectHeaderValue(HeaderParameterNames.ALGORITHM) == null) {
            LOG.warn("alg header shall be present for JAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // cty (Conditional presence)
        if (signature.isCounterSignature() && headers.getObjectHeaderValue(HeaderParameterNames.CONTENT_TYPE) != null) {
            LOG.warn("cty header shall not be present for a JAdES-BASELINE-B counter signature!");
            return false;
        }
        // crit (conditional presence, but shall be included for other mandatory headers, therefore it is mandatory)
        if (headers.getObjectHeaderValue(HeaderParameterNames.CRITICAL) == null) {
            LOG.warn("crit header shall be present for a JAdES-BASELINE-B signature!");
            return false;
        }
        // sigT (Cardinality == 1)
        if (headers.getObjectHeaderValue(JAdESHeaderParameterNames.SIG_T) == null) {
            LOG.warn("sigT header shall be present for JAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // x5t#256 / x5t#o / sigX5ts (Cardinality == 1)
        int certHeaders = 0;
        if (headers.getObjectHeaderValue(HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT) != null) ++certHeaders;
        if (headers.getObjectHeaderValue(JAdESHeaderParameterNames.X5T_O) != null) ++certHeaders;
        if (headers.getObjectHeaderValue(JAdESHeaderParameterNames.SIG_X5T_S) != null) ++certHeaders;
        if (certHeaders != 1) {
            LOG.warn("Only one of x5t#256, x5t#o, sigX5ts headers shall be present " +
                    "for JAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // sigPSt (Cardinality 0 or 1)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.SIG_PST).size() > 1) {
            LOG.warn("Only one sigPSt header shall be present for JAdES-BASELINE-B signature (cardinality 0 or 1)!");
            return false;
        }
        // Additional requirement (b)
        if (!isSignaturePolicyIdentifierHashPresent() && signature.getSignaturePolicyStore() != null) {
            LOG.warn("sigPSt header shall not be incorporated " +
                    "for JAdES-BASELINE-B signature with not defined sigPId/hashAV (requirement (b))!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineTProfile() {
        if (!minimalTRequirement()) {
            return false;
        }
        JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
        // Additional requirement (c)
        for (EtsiUComponent etsiUComponent :
                DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.SIG_TST)) {
            Map<?, ?> sigTst = (Map<?, ?>) etsiUComponent.getValue();
            List<?> tstTokens = (List<?>) sigTst.get(JAdESHeaderParameterNames.TST_TOKENS);
            if (tstTokens.size() != 1) {
                LOG.warn("sigTst shall contain only one electronic timestamp for JAdES-BASELINE-T signature (requirement (c))!");
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTProfile() {
        if (!minimalLTRequirement()) {
            return false;
        }
        JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
        // xRefs (Cardinality == 0)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.X_REFS).size() > 0) {
            LOG.warn("xRefs header shall not be present for JAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // axRefs (Cardinality == 0)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.AX_REFS).size() > 0) {
            LOG.warn("axRefs header shall not be present for JAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // rRefs (Cardinality == 0)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.R_REFS).size() > 0) {
            LOG.warn("rRefs header shall not be present for JAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // arRefs (Cardinality == 0)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.AR_REFS).size() > 0) {
            LOG.warn("arRefs header shall not be present for JAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // sigRTst (Cardinality == 0)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.SIG_R_TST).size() > 0) {
            LOG.warn("sigRTst header shall not be present for JAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        // rfsTst (Cardinality == 0)
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.RFS_TST).size() > 0) {
            LOG.warn("rfsTst header shall not be present for JAdES-BASELINE-LT signature (cardinality == 0)!");
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTAProfile() {
        return minimalLTARequirement();
    }

}
