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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Verifies validity of the performed evidence record validation process
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class EvidenceRecordValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The evidence record to check */
    private final EvidenceRecordWrapper evidenceRecord;

    /** Evidence record validation result */
    private final XmlValidationProcessEvidenceRecord erValidationResult;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link T}
     * @param evidenceRecord {@link EvidenceRecordWrapper}
     * @param erValidationResult {@link XmlValidationProcessEvidenceRecord}
     * @param constraint {@link LevelConstraint}
     */
    public EvidenceRecordValidationCheck(I18nProvider i18nProvider, T result, EvidenceRecordWrapper evidenceRecord,
                                         XmlValidationProcessEvidenceRecord erValidationResult, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, evidenceRecord.getId());
        this.evidenceRecord = evidenceRecord;
        this.erValidationResult = erValidationResult;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.ER;
    }

    @Override
    protected boolean process() {
        return isValid(erValidationResult);
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(erValidationResult.getProofOfExistence().getTime());
        return i18nProvider.getMessage(MessageTag.EVIDENCE_RECORD_VALIDATION, evidenceRecord.getId(), date);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_IRERVPC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_IRERVPC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return erValidationResult.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return erValidationResult.getConclusion().getSubIndication();
    }

}
