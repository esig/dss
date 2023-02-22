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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This class verifies whether a used {@code eu.europa.esig.dss.enumerations.DigestAlgorithm}
 * for a signing-certificate-reference signing-attribute is reliable and acceptable at validation time
 *
 */
public class SigningCertificateRefDigestCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion>
        extends DigestCryptographicCheckerResultCheck<T> {

    /** The certificate reference being validated */
    private final CertificateRefWrapper certificateRefWrapper;

    /** Defines the check level */
    private final LevelConstraint constraint;

    /** The checker result message */
    private final XmlMessage checkerResultMessage;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param validationDate {@link Date}
     * @param certificateRefWrapper {@link CertificateRefWrapper}
     * @param ccResult {@link XmlCC}
     * @param constraint {@link LevelConstraint}
     */
    public SigningCertificateRefDigestCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result,
                    Date validationDate, CertificateRefWrapper certificateRefWrapper,
                    XmlCC ccResult, LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, MessageTag.ACCM_POS_SIG_CERT_REF, ccResult, constraint);
        this.certificateRefWrapper = certificateRefWrapper;
        this.constraint = constraint;
        this.checkerResultMessage = extractXmlMessage(ccResult, constraint);
    }

    private static XmlMessage extractXmlMessage(XmlCC ccResult, LevelConstraint constraint) {
        XmlConclusion conclusion = ccResult.getConclusion();
        if (conclusion != null && constraint != null && constraint.getLevel() != null) {
            // Collects messages from higher levels only
            List<XmlMessage> messages = new ArrayList<>();
            switch (constraint.getLevel()) {
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
    protected String buildAdditionalInfo() {
        String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
        if (isValid(ccResult)) {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_ID,
                    ccResult.getVerifiedAlgorithm().getName(), dateTime, position, certificateRefWrapper.getCertificateId());
        } else {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID,
                    getErrorMessage(), dateTime, position, certificateRefWrapper.getCertificateId());
        }
    }

    @Override
    protected Level getLevel() {
        if (constraint != null) {
            return constraint.getLevel();
        }
        return null;
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return checkerResultMessage;
    }

}
