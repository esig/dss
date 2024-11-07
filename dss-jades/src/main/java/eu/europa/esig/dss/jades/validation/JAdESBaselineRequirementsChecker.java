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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.BaselineRequirementsChecker;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Performs checks according to EN 119 182-1 v1.1.1
 * "6.3 Requirements on JAdES components and services"
 *
 */
public class JAdESBaselineRequirementsChecker extends BaselineRequirementsChecker<JAdESSignature> {

    private static final Logger LOG = LoggerFactory.getLogger(JAdESBaselineRequirementsChecker.class);

    /** 2025-07-15T00:00:00Z date, see TS 119 182-1 */
    private static final Date SIG_T_OBSOLESCENCE_DATE = DSSUtils.getUtcDate(2025, Calendar.JULY, 15);

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
        JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
        // alg (Cardinality == 1)
        if (Utils.isStringEmpty(jws.getProtectedHeaderValueAsString(HeaderParameterNames.ALGORITHM))) {
            LOG.warn("alg header shall be present for JAdES-BASELINE-B signature (cardinality == 1)!");
            return false;
        }
        // cty (Conditional presence)
        if (signature.isCounterSignature() && Utils.isStringNotEmpty(jws.getProtectedHeaderValueAsString(HeaderParameterNames.CONTENT_TYPE))) {
            LOG.warn("cty header shall not be present for a JAdES-BASELINE-B counter signature!");
            return false;
        }
        // verify 'crit' as of RFC 7515 and ETSI TS 119 182-1
        if (!critRequirements(jws)) {
            // validation errors returned inside
            return false;
        }
        // sigT (Cardinality == 1)
        if (!signingTimeRequirement(jws)) {
            return false;
        }
        // x5t#256 / x5t#o / sigX5ts (Cardinality == 1)
        int certHeaders = 0;
        if (Utils.isStringNotEmpty(jws.getProtectedHeaderValueAsString(HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT))) ++certHeaders;
        if (Utils.isMapNotEmpty(jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.X5T_O))) ++certHeaders;
        if (Utils.isCollectionNotEmpty(jws.getProtectedHeaderValueAsList(JAdESHeaderParameterNames.SIG_X5T_S))) ++certHeaders;
        if (certHeaders != 1) {
            LOG.warn("One and only one of x5t#256, x5t#o, sigX5ts headers shall be present " +
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

    private boolean critRequirements(JWS jws) {
        List<?> critList = new ArrayList<>();

        // crit (conditional presence, required only for some elements)
        Object crit = jws.getHeaders().getObjectHeaderValue(HeaderParameterNames.CRITICAL);
        if (crit != null) {
            // crit shall be an array (List)
            if (!(crit instanceof List<?>)) {
                LOG.warn("crit header shall be an instance of json array type for a JAdES-BASELINE-B signature!");
                return false;
            }
            // crit cannot be empty
            critList = (List<?>) crit;
            if (Utils.isCollectionEmpty(critList)) {
                LOG.warn("crit header shall not be empty for a JAdES-BASELINE-B signature (see RFC 7515)!");
                return false;
            }
            Set<Object> uniqueEntries = new HashSet<>();
            Set<Object> duplicates = critList.stream().filter(e -> !uniqueEntries.add(e)).collect(Collectors.toSet());
            if (Utils.isCollectionNotEmpty(duplicates)) {
                LOG.warn("crit header shall not contain duplicates for a JAdES-BASELINE-B signature (see RFC 7515)! Found duplicates : '{}'", duplicates);
                return false;
            }
        }

        Set<String> keySet = DSSJsonUtils.extractJOSEHeaderMembersSet(jws);
        for (String key : keySet) {
            // critical headers shall not be present within crit
            if (DSSJsonUtils.isCriticalHeaderException(key)) {
                if (critList.contains(key)) {
                    LOG.warn("crit header shall not contain headers listed in RFC 7515 or RFC 7518 " +
                            "for a JAdES-BASELINE-B signature (see RFC 7515)! Found header : '{}'", key);
                    return false;
                }

            } else if (DSSJsonUtils.isRequiredCriticalHeader(key)) {
                if (crit == null) {
                    LOG.warn("crit header shall be present when '{}' header is present in a signature for a JAdES-BASELINE-B signature!", key);
                    return false;
                } else if (!critList.contains(key)) {
                    LOG.warn("crit header shall contain '{}' header when present in a signature for a JAdES-BASELINE-B signature!", key);
                    return false;
                }
            }
        }
        for (Object critEntry : critList) {
            // crit shall contain String entries
            if (!(critEntry instanceof String)) {
                LOG.warn("An entry of crit header shall be an instance of String type for a JAdES-BASELINE-B signature!");
                return false;
            }
            // crit shall not contain not-used entries
            if (!keySet.contains(critEntry)) {
                LOG.warn("crit header can contain only entries used within a signed header " +
                        "for a JAdES-BASELINE-B signature (see RFC 7515)! Found header : '{}'", critEntry);
                return false;
            }
            //  Conforming implementations must reject input containing critical
            //  extensions that are not understood or cannot be processed.
            if (!DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(critEntry) &&
                    !JAdESHeaderParameterNames.ETSI_U.equals(critEntry)) {
                LOG.warn("crit header shall not contain a header that cannot be understood and processed " +
                        "for a JAdES-BASELINE-B signature (see RFC 7515)! Found header : '{}'", critEntry);
                return false;
            }
        }
        return true;
    }

    private boolean signingTimeRequirement(JWS jws) {
        /*
         * a) Requirements for iat and sigT. Before 2025-07-15T00:00:00Z the generator should include
         *    the iat header parameter for indicating the claimed signing time in new JAdES signatures
         *    and should not include the iat header parameter for indicating the claimed signing time
         *    in new JAdES signatures. Starting at 2025-07-15T00:00:00Z the generator shall include the
         *    iat header parameter for indicating the claimed signing time in new JAdES signatures.
         */
        Number iat = jws.getProtectedHeaderValueAsNumber(JAdESHeaderParameterNames.IAT);
        String sigT = jws.getProtectedHeaderValueAsString(JAdESHeaderParameterNames.SIG_T);
        Date signingTime = signature.getSigningTime();

        // iat or sigT (Cardinality == 1)
        if (iat == null && Utils.isStringEmpty(sigT)) {
            LOG.warn("Either iat header or sigT header (for signatures before 2025-07-15T00:00:00Z) shall be present " +
                    "for JAdES-BASELINE-B signature (cardinality == 1)!");
            return false;

        } else if (signingTime == null) {
            LOG.warn("Invalid date format extracted from {} header parameter for JAdES-BASELINE-B signature (cardinality == 1)!",
                    iat != null ? "iat" : "sigT");
            return false;

        } else if (iat == null) {
            if (signingTime.before(SIG_T_OBSOLESCENCE_DATE)) {
                LOG.debug("iat header should be present for JAdES-BASELINE-B signature produced before 2025-07-15T00:00:00Z (cardinality == 0 or 1)!");
            } else {
                LOG.warn("iat header shall be present for JAdES-BASELINE-B signature produced starting at 2025-07-15T00:00:00Z (cardinality == 1)!");
                return false;
            }

        } else if (Utils.isStringNotEmpty(sigT)) {
            LOG.warn("Both iat and sigT headers are not allowed for JAdES-BASELINE-B signature (cardinality == 1)!");
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
            Map<?, ?> sigTst = DSSJsonUtils.toMap(etsiUComponent.getValue(), JAdESHeaderParameterNames.SIG_TST);
            List<?> tstTokens = DSSJsonUtils.getAsList(sigTst, JAdESHeaderParameterNames.TST_TOKENS);
            if (tstTokens.size() != 1) {
                LOG.warn("sigTst shall contain only one electronic timestamp for JAdES-BASELINE-T signature (requirement (c))!");
                return false;
            }
        }
        // Additional requirement (d)
        if (!signatureTimestampsCreatedBeforeSignCertExpiration()) {
            LOG.warn("sigTst shall be created before expiration of the signing-certificate " +
                    "for JAdES-BASELINE-T signature (requirement (d))!");
            return false;
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
    protected boolean containsLTLevelCertificates() {
        JAdESEtsiUHeader etsiUHeader = signature.getEtsiUHeader();
        if (DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.X_VALS).size() +
                DSSJsonUtils.getUnsignedPropertiesWithHeaderName(etsiUHeader, JAdESHeaderParameterNames.AX_VALS).size() == 0) {
            return false;
        }
        return true;
    }

    @Override
    public boolean hasBaselineLTAProfile() {
        return minimalLTARequirement();
    }

}
