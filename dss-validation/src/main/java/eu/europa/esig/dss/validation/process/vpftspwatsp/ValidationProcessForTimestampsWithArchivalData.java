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
package eu.europa.esig.dss.validation.process.vpftspwatsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.MessageImprintDigestAlgorithmValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.TimestampAcceptanceValidation;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TimestampAcceptanceValidationResultCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POE;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.EvidenceRecordValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;
import eu.europa.esig.dss.validation.process.vpftsp.checks.BasicTimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.AcceptableBasicTimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.MessageImprintDigestAlgorithmValidationCheck;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.PastTimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.TimestampMessageImprintCheck;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * This class validates a timestamp with a provided archival data (POE)
 *
 */
public class ValidationProcessForTimestampsWithArchivalData extends Chain<XmlValidationProcessArchivalDataTimestamp> {

    /** Timestamp validation with long-term data result */
    private final XmlValidationProcessBasicTimestamp vpftsp;

    /** The timestamp */
    private final TimestampWrapper timestamp;

    /** Map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Map of processed evidence records */
    private final Map<String, XmlEvidenceRecord> evidenceRecordValidations;

    /** The current time of validation */
    private final Date currentTime;

    /** Validation policy */
    private final ValidationPolicy policy;

    /** The POE container */
    private final POEExtraction poe;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param timestamp {@link TimestampWrapper}
     * @param vpftsp {@link XmlValidationProcessBasicTimestamp}
     * @param bbbs map of BasicBuildingBlocks
     * @param evidenceRecordValidations a map of evidence record identifiers and their corresponding validation results
     * @param currentTime {@link Date} validation time
     * @param policy {@link ValidationPolicy}
     * @param poe {@link POEExtraction}
     */
    public ValidationProcessForTimestampsWithArchivalData(final I18nProvider i18nProvider, final TimestampWrapper timestamp,
            final XmlValidationProcessBasicTimestamp vpftsp, final Map<String, XmlBasicBuildingBlocks> bbbs,
            final Map<String, XmlEvidenceRecord> evidenceRecordValidations, final Date currentTime,
            final ValidationPolicy policy, final POEExtraction poe) {
        super(i18nProvider, new XmlValidationProcessArchivalDataTimestamp());
        this.vpftsp = vpftsp;
        this.timestamp = timestamp;
        this.bbbs = bbbs;
        this.evidenceRecordValidations = evidenceRecordValidations;
        this.currentTime = currentTime;
        this.policy = policy;
        this.poe = poe;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPFTSPWATSP;
    }

    @Override
    protected void initChain() {
        XmlProofOfExistence lowestPOE = getLowestPOE();
        Date lowestPOETime = lowestPOE.getTime();
        result.setProofOfExistence(lowestPOE);

        XmlConclusion basicTimestampConclusion = vpftsp.getConclusion();

        ChainItem<XmlValidationProcessArchivalDataTimestamp> item = null;

        /* Step 0. Execute detached evidence records processing, when applicable */
        List<EvidenceRecordWrapper> evidenceRecords = timestamp.getEvidenceRecords();
        if (Utils.isCollectionNotEmpty(evidenceRecords)) {
            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
                XmlValidationProcessEvidenceRecord evidenceRecordValidation = getEvidenceRecordValidation(evidenceRecord);
                if (evidenceRecordValidation != null) {

                    ChainItem<XmlValidationProcessArchivalDataTimestamp> evidenceRecordValidationConclusive =
                            evidenceRecordValidationConclusive(evidenceRecord, evidenceRecordValidation);

                    if (item == null) {
                        item = firstItem = evidenceRecordValidationConclusive;
                    } else {
                        item = item.setNextItem(evidenceRecordValidationConclusive);
                    }

                    if (isValid(evidenceRecordValidation)) {
                        poe.extractPOE(evidenceRecord);
                    }

                }
            }
        }

        ChainItem<XmlValidationProcessArchivalDataTimestamp> timestampBasicSignatureValidationAcceptable =
                timestampBasicSignatureValidationAcceptable(vpftsp);
        if (item == null) {
            item = firstItem = timestampBasicSignatureValidationAcceptable;
        } else {
            item = item.setNextItem(timestampBasicSignatureValidationAcceptable);
        }

        if (ValidationProcessUtils.isAllowedBasicTimestampValidation(basicTimestampConclusion)) {

            item = item.setNextItem(timestampBasicSignatureValidationConclusive(timestamp, vpftsp));

            MessageImprintDigestAlgorithmValidation midav = timestampDigestAlgorithmValidation(timestamp, lowestPOETime);
            XmlSAV davResult = midav.execute();

            /*
             * b) If PASSED is returned and a POE exists for the time-stamp for a time when the cryptographic hash
             * function used in the time-stamp (messageImprint.hashAlgorithm) has been considered reliable, the SVA
             * shall perform the POE extraction process (clause 5.6.2.3) with the signature, the time-stamp and the
             * cryptographic constraints as inputs. The SVA shall add the returned POEs to the set of POEs.
             */
            if (isValid(vpftsp)) {

                item = item.setNextItem(messageImprintDigestAlgorithm(timestamp, davResult, lowestPOETime));

                if (isValid(davResult)) {

                    item = item.setNextItem(timestampMessageImprint(timestamp));

                    // NOTE: POE is extracted outside the class

                }

            }

            /*
             * c) If the output of the validation is INDETERMINATE/REVOKED_NO_POE,
             * INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE,
             * INDETERMINATE/OUT_OF_BOUNDS_NOT_REVOKED,
             * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE or
             * INDETERMINATE/REVOCATION_OUT_OF_BOUNDS_NO_POE,, the SVA shall perform past
             * signature validation process (as per clause 5.6.2.4) with the following inputs: the time-stamp, the
             * indication/sub-indication returned by the time-stamp validation process in step 5)a), the TSA's certificate,
             * the X.509 validation parameters, X.509 validation constraints, cryptographic constraints, certificate
             * validation data and the set of POEs. Then:
             *
             * i)    If it returns PASSED the SVA shall determine from the set of POEs the earliest time the existence
             *       of the time-stamp can be proven.
             *
             * ii)   The SVA shall perform the Signature Acceptance Validation process as per clause 5.2.8 with the
             *       following inputs:
             *       - The Signed Data Object(s).
             *       - The time determined in step i) above as the validation time parameter.
             *       - The Cryptographic Constraints.
             *       If the Signature Acceptance Validation process returns PASSED, the SVA shall go to the next step.
             *       Otherwise, the SVA shall go to step d).
             *
             * iii) If a POE exists for the time-stamp for a time when the cryptographic hash function used in the
             *      time-stamp has been considered reliable, the SVA shall perform the POE extraction process
             *      (clause 5.6.2.3) and shall add the returned POEs to the set of POEs, and shall continue with
             *      step 5)a) using the next time-stamp attribute.
             */
            else if (ValidationProcessUtils.isAllowedBasicTimestampValidation(davResult.getConclusion())) {

                PastSignatureValidation psv = new PastSignatureValidation(i18nProvider, timestamp, bbbs,
                        basicTimestampConclusion, poe, currentTime, policy, Context.TIMESTAMP);
                XmlPSV psvResult = psv.execute();

                XmlBasicBuildingBlocks tstBBB = bbbs.get(timestamp.getId());
                enrichBBBWithPSVConclusion(tstBBB, psvResult);

                item = item.setNextItem(pastTimestampValidation(timestamp, psvResult));

                /*
                 * If it returns PASSED and the cryptographic hash function used in the time-stamp is considered
                 * reliable at the generation time of the time-stamp, the long term validation process shall
                 * perform the POE extraction process and shall add the returned POEs to the set of POEs
                 * continue with step 5a using the next timestamp attribute.
                 */
                if (isValid(psvResult)) {

                    item = item.setNextItem(timestampIsAcceptable(timestamp, lowestPOETime));

                    item = item.setNextItem(messageImprintDigestAlgorithm(timestamp, davResult, lowestPOETime));

                    if (isValid(davResult)) {

                        item = item.setNextItem(timestampMessageImprint(timestamp));

                        // NOTE: POE is extracted outside the class

                    }
                }
            }
        }

    }

    private XmlProofOfExistence getLowestPOE() {
        POE lowestPOE = poe.getLowestPOE(timestamp.getId());
        XmlProofOfExistence xmlProofOfExistence = new XmlProofOfExistence();
        xmlProofOfExistence.setTime(lowestPOE.getTime());
        return xmlProofOfExistence;
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> timestampBasicSignatureValidationAcceptable(
            XmlValidationProcessBasicTimestamp timestampValidationResult) {
        return new AcceptableBasicTimestampValidationCheck<>(i18nProvider, result, timestampValidationResult, getFailLevelConstraint());
    }

    private void enrichBBBWithPSVConclusion(XmlBasicBuildingBlocks bbb, XmlPSV psv) {
        bbb.setPSV(psv);

        XmlConclusion bbbConclusion = bbb.getConclusion();
        XmlConclusion psvConclusion = psv.getConclusion();
        bbbConclusion.setIndication(psvConclusion.getIndication());
        bbbConclusion.setSubIndication(psvConclusion.getSubIndication());
        bbbConclusion.getErrors().addAll(psvConclusion.getErrors());
        bbbConclusion.getWarnings().addAll(psvConclusion.getWarnings());
        bbbConclusion.getInfos().addAll(psvConclusion.getInfos());
    }

    private XmlValidationProcessEvidenceRecord getEvidenceRecordValidation(EvidenceRecordWrapper evidenceRecord) {
        XmlEvidenceRecord xmlEvidenceRecord = evidenceRecordValidations.get(evidenceRecord.getId());
        return xmlEvidenceRecord.getValidationProcessEvidenceRecord();
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> evidenceRecordValidationConclusive(
            EvidenceRecordWrapper evidenceRecordWrapper, XmlValidationProcessEvidenceRecord erValidationResult) {
        return new EvidenceRecordValidationCheck<>(i18nProvider, result, evidenceRecordWrapper,
                erValidationResult, getEvidenceRecordValidationConstraintLevel());
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> timestampBasicSignatureValidationConclusive(
            TimestampWrapper timestampWrapper, XmlValidationProcessBasicTimestamp timestampValidationResult) {
        return new BasicTimestampValidationCheck<>(i18nProvider, result, timestampWrapper,
                timestampValidationResult, getWarnLevelConstraint());
    }

    private MessageImprintDigestAlgorithmValidation timestampDigestAlgorithmValidation(
            TimestampWrapper newestTimestamp, Date poeTime) {
        CryptographicConstraint cryptographicConstraint = policy.getSignatureCryptographicConstraint(Context.TIMESTAMP);
        return new MessageImprintDigestAlgorithmValidation(i18nProvider, poeTime,
                newestTimestamp.getMessageImprint().getDigestMethod(), cryptographicConstraint);
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> pastTimestampValidation(TimestampWrapper timestamp, XmlPSV xmlPSV) {
        return new PastTimestampValidationCheck<>(i18nProvider, result, timestamp, xmlPSV, getFailLevelConstraint());
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> messageImprintDigestAlgorithm(
            TimestampWrapper timestampWrapper, XmlSAV davResult, Date poeTime) {
        return new MessageImprintDigestAlgorithmValidationCheck<>(i18nProvider, result, timestampWrapper,
                davResult, poeTime, getWarnLevelConstraint());
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> timestampMessageImprint(TimestampWrapper timestampWrapper) {
        return new TimestampMessageImprintCheck<>(i18nProvider, result, timestampWrapper, getWarnLevelConstraint());
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> timestampIsAcceptable(TimestampWrapper timestamp, Date lowestPOE) {
        TimestampAcceptanceValidation tav = new TimestampAcceptanceValidation(i18nProvider, lowestPOE, timestamp, policy);
        XmlSAV savResult = tav.execute();
        return new TimestampAcceptanceValidationResultCheck<>(i18nProvider, result, savResult, getFailLevelConstraint());
    }

    private LevelConstraint getEvidenceRecordValidationConstraintLevel() {
        LevelConstraint constraint = policy.getEvidenceRecordValidConstraint();
        if (constraint == null) {
            constraint = getWarnLevelConstraint();
        }
        return constraint;
    }

    @Override
    protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
        if ((XmlBlockType.TST_BBB.equals(constraint.getBlockType()) || XmlBlockType.TST_PSV.equals(constraint.getBlockType())) &&
                policy.getTimestampValidConstraint() == null) {
            // skip propagating of validation messages for TSTs in default processing
        } else {
            super.collectMessages(conclusion, constraint);
        }
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        if (!ValidationProcessUtils.isAllowedBasicTimestampValidation(vpftsp.getConclusion())) {
            conclusion.getWarnings().addAll(vpftsp.getConclusion().getWarnings());
            conclusion.getInfos().addAll(vpftsp.getConclusion().getInfos());
        }
    }

}
