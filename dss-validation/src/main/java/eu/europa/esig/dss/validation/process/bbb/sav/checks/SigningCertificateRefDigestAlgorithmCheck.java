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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestCryptographicChecker;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * This class verifies whether a used {@code eu.europa.esig.dss.enumerations.DigestAlgorithm}
 * for a signing-certificate-reference signing-attribute is reliable and acceptable at validation time
 *
 * @param <T> {@code XmlConstraintsConclusion} implementation of the block's conclusion
 */
public class SigningCertificateRefDigestAlgorithmCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The certificate references being validated */
    private final List<CertificateRefWrapper> certificateRefs;

    /** Id of the certificate being validated */
    private final String certificateId;

    /** Validation time */
    private final Date validationDate;

    /** Validation context */
    private final Context context;

    /** SubContext */
    private final SubContext subContext;

    /** Validation policy */
    private final ValidationPolicy validationPolicy;

    /** Defines the check level */
    private final LevelRule constraint;

    /** The final validation result */
    private XmlCC cryptographicValidationResult;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param validationDate {@link Date}
     * @param certificateRefs a list of {@link CertificateRefWrapper}s to be validated
     * @param certificateId {@link String} identifier of the related certificate
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @param validationPolicy {@link ValidationPolicy}
     * @param constraint {@link LevelRule}
     */
    public SigningCertificateRefDigestAlgorithmCheck(I18nProvider i18nProvider, T result, Date validationDate,
            List<CertificateRefWrapper> certificateRefs, String certificateId, Context context, SubContext subContext,
            ValidationPolicy validationPolicy, LevelRule constraint) {
        super(i18nProvider, result, constraint, certificateId);
        this.certificateRefs = certificateRefs;
        this.certificateId = certificateId;
        this.validationPolicy = validationPolicy;
        this.validationDate = validationDate;
        this.context = context;
        this.subContext = subContext;
        this.constraint = constraint;
    }

    @Override
    protected boolean process() {
        XmlCC ccResult = validateCertReferences();
        return ccResult != null && isValid(ccResult);
    }

    /**
     * This method performs validation of the signing certificate references' digest algorithms
     *
     * @return {@link XmlCC} validation result
     */
    protected XmlCC validateCertReferences() {
        if (cryptographicValidationResult != null) {
            return cryptographicValidationResult;
        }

        for (CertificateRefWrapper certificateRefWrapper : certificateRefs) {
            DigestAlgorithm digestAlgorithm = certificateRefWrapper.getDigestMethod();
            if (digestAlgorithm == null) {
                continue;
            }

            XmlCC dacResult = getSigningCertificateDigestCryptographicCheckResult(certificateRefWrapper);

            // overwrite only if previous checks are secure
            if (cryptographicValidationResult == null || !isValid(cryptographicValidationResult)) {
                cryptographicValidationResult = dacResult;
            }

            if (isValid(cryptographicValidationResult)) {
                break;
            }
        }
        return cryptographicValidationResult;
    }

    private XmlCC getSigningCertificateDigestCryptographicCheckResult(CertificateRefWrapper certificateRef) {
        CryptographicSuite certificateConstraint = validationPolicy.getCertificateCryptographicConstraint(context, subContext);
        DigestCryptographicChecker dac = new DigestCryptographicChecker(i18nProvider, certificateRef.getDigestMethod(),
                validationDate, MessageTag.ACCM_POS_SIG_CERT_REF, certificateConstraint);
        return dac.execute();
    }

    @Override
    protected XmlMessage buildConstraintMessage() {
        return buildXmlMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF);
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return extractXmlMessage();
    }

    /**
     * Gets error message
     *
     * @return {@link String}, or empty string if check succeeded
     */
    protected String getErrorMessage() {
        XmlMessage errorMessage = buildErrorMessage();
        return errorMessage != null ? errorMessage.getValue() : Utils.EMPTY_STRING;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        if (cryptographicValidationResult != null) {
            return cryptographicValidationResult.getConclusion().getIndication();
        } else {
            return Indication.INDETERMINATE;
        }
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        if (cryptographicValidationResult != null) {
            return cryptographicValidationResult.getConclusion().getSubIndication();
        } else {
            return SubIndication.CRYPTO_CONSTRAINTS_FAILURE;
        }
    }

    @Override
    protected String buildAdditionalInfo() {
        String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
        if (isValid(cryptographicValidationResult)) {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_ID,
                    cryptographicValidationResult.getVerifiedAlgorithm().getName(), dateTime, MessageTag.ACCM_POS_SIG_CERT_REF, certificateId);
        } else {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID,
                    getErrorMessage(), dateTime, MessageTag.ACCM_POS_SIG_CERT_REF, certificateId);
        }
    }

    @Override
    protected List<XmlMessage> getPreviousErrors() {
        if (cryptographicValidationResult != null) {
            return cryptographicValidationResult.getConclusion().getErrors();
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    protected Level getLevel() {
        if (constraint != null) {
            Level currentConstraintLevel = constraint.getLevel();
            Level subProcessLevel = getSubProcessLevel();
            return getLowestLevel(currentConstraintLevel, subProcessLevel);
        }
        return null;
    }

    private Level getSubProcessLevel() {
        XmlConclusion conclusion = getCryptographicValidationResult().getConclusion();
        if (conclusion != null) {
            if (Utils.isCollectionNotEmpty(conclusion.getErrors())) {
                return Level.FAIL;
            } else if (Utils.isCollectionNotEmpty(conclusion.getWarnings())) {
                return Level.WARN;
            } else if (Utils.isCollectionNotEmpty(conclusion.getInfos())) {
                return Level.INFORM;
            }
        }
        return null;
    }

    private Level getLowestLevel(Level currentLevel, Level subProcessLevel) {
        if (currentLevel == null) {
            return subProcessLevel;
        } else if (subProcessLevel == null) {
            return currentLevel;
        } else if (Level.INFORM == currentLevel || Level.INFORM == subProcessLevel) {
            return Level.INFORM;
        } else if (Level.WARN == currentLevel || Level.WARN == subProcessLevel) {
            return Level.WARN;
        } else if (Level.FAIL == currentLevel || Level.FAIL == subProcessLevel) {
            return Level.FAIL;
        }
        return currentLevel;
    }

    private XmlMessage extractXmlMessage() {
        XmlConclusion conclusion = cryptographicValidationResult.getConclusion();
        if (conclusion != null) {
            // Collects messages from higher levels only
            List<XmlMessage> messages = new ArrayList<>();
            switch (getLevel()) {
                case INFORM:
                    messages.addAll(conclusion.getInfos());
                    messages.addAll(conclusion.getWarnings());
                    messages.addAll(conclusion.getErrors());
                    break;
                case WARN:
                    messages.addAll(conclusion.getWarnings());
                    messages.addAll(conclusion.getErrors());
                    break;
                case FAIL:
                    messages.addAll(conclusion.getErrors());
                    break;
                default:
                    break;
            }
            if (Utils.isCollectionNotEmpty(messages)) {
                return messages.iterator().next(); // take the first one
            }
        }
        return null;
    }

    @Override
    protected boolean isValid(XmlConstraintsConclusion constraintConclusion) {
        return super.isValid(constraintConclusion) && allConstraintsValid(constraintConclusion);
    }

    private boolean allConstraintsValid(XmlConstraintsConclusion result) {
        List<XmlConstraint> constraints = result.getConstraint();
        if (Utils.isCollectionNotEmpty(constraints)) {
            for (XmlConstraint constraint : constraints) {
                if (!XmlStatus.OK.equals(constraint.getStatus()) && !XmlStatus.IGNORED.equals(constraint.getStatus())) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Gets the final cryptographic validation result
     *
     * @return {@link XmlCC}
     */
    public XmlCC getCryptographicValidationResult() {
        return validateCertReferences();
    }

}
