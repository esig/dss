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
package eu.europa.esig.dss.validation.process.attestation.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Verified whether the validation time is within attestation administrative validity period range
 *
 */
public class AttestationAdministrativePeriodNotExpiredCheck extends ChainItem<XmlSAV> {

    /** attestation to check */
    private final AttestationWrapper attestation;

    /** attestation validation time */
    private final Date validationTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param attestation {@link AttestationWrapper}
     * @param validationTime {@link Date}
     * @param constraint {@link LevelRule}
     */
    public AttestationAdministrativePeriodNotExpiredCheck(I18nProvider i18nProvider, XmlSAV result,
                                                          AttestationWrapper attestation, Date validationTime, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.attestation = attestation;
        this.validationTime = validationTime;
    }

    @Override
    protected boolean process() {
        return notAdministrativePeriodBefore() && notAdministrativePeriodAtOrAfter();
    }

    private boolean notAdministrativePeriodBefore() {
        /*
         * Same logic is applied as for IETF RFC 7519 "nbf" mutatis mutandis
         */
        return attestation.getAdministrativeIssuanceDate() != null && !validationTime.before(attestation.getAdministrativeIssuanceDate());
    }

    private boolean notAdministrativePeriodAtOrAfter() {
        /*
         * Same logic is applied as for IETF RFC 7519 "exp" mutatis mutandis
         */
        return attestation.getAdministrativeExpirationDate() != null && validationTime.before(attestation.getAdministrativeExpirationDate());
    }

    @Override
    protected String buildAdditionalInfo() {
        if (!notAdministrativePeriodBefore() || !notAdministrativePeriodAtOrAfter()) {
            return i18nProvider.getMessage(MessageTag.EAA_VT_IAVR_VALIDITY,
                    ValidationProcessUtils.getFormattedDate(validationTime),
                    ValidationProcessUtils.getFormattedDate(attestation.getAdministrativeIssuanceDate()),
                    ValidationProcessUtils.getFormattedDate(attestation.getAdministrativeExpirationDate()));
        }
        return null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_VT_IAVR;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_VT_IAVR_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.OUT_OF_BOUNDS_NO_POE;
    }

}
