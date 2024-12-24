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
package eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.AtLeastOneReferenceDataObjectFoundCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataGroupCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestMatcherListCryptographicChainBuilder;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.TimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord.checks.EvidenceRecordSignedAndTimestampedFilesCoveredCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord.checks.EvidenceRecordSignedFilesCoveredCheck;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Performs Evidence Record validation as per clause 5.6.3 "Validation Process for Signatures providing
 * Long Term Availability and Integrity of Validation Material", step 1) 5.6.3.4 "Processing"
 *
 */
public class EvidenceRecordValidationProcess extends Chain<XmlValidationProcessEvidenceRecord> {

    /**
     * Diagnostic data
     */
    private final DiagnosticData diagnosticData;

    /**
     * Evidence record being validated
     */
    private final EvidenceRecordWrapper evidenceRecord;

    /**
     * Collection of timestamps
     */
    private final Collection<XmlTimestamp> xmlTimestamps;

    /**
     * Map of BasicBuildingBlocks
     */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /**
     * Validation policy used to validate evidence records
     */
    private final ValidationPolicy policy;

    /**
     * Validation time
     */
    private final Date currentTime;

    /**
     * Common constructor
     *
     * @param i18nProvider the access to translations
     * @param diagnosticData {@link DiagnosticData}
     * @param evidenceRecord {@link EvidenceRecordWrapper} to be validated
     * @param xmlTimestamps a collection of {@link XmlTimestamp} validations
     * @param bbbs a map of performed {@link XmlBasicBuildingBlocks}s
     * @param validationPolicy {@link ValidationPolicy} to be used
     * @param currentTime {@link Date} validation time
     */
    public EvidenceRecordValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData, EvidenceRecordWrapper evidenceRecord,
                                           Collection<XmlTimestamp> xmlTimestamps, Map<String, XmlBasicBuildingBlocks> bbbs,
                                           ValidationPolicy validationPolicy, Date currentTime) {
        super(i18nProvider, new XmlValidationProcessEvidenceRecord());

        this.diagnosticData = diagnosticData;
        this.evidenceRecord = evidenceRecord;
        this.xmlTimestamps = xmlTimestamps;
        this.bbbs = bbbs;
        this.policy = validationPolicy;
        this.currentTime = currentTime;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPER;
    }

    @Override
    protected void initChain() {

        ChainItem<XmlValidationProcessEvidenceRecord> item = null;

        /*
         * 5.6.3.4 Processing
         *
         * a) The process shall take the first ER that was not yet processed.
         *
         * b) The process shall verify this ER according to IETF RFC 4998 [i.9] or IETF RFC 6283 [i.10] taking into
         * account the following additional requirements when validating a time-stamp token at the time of the
         * following Archive Timestamp:
         */
        List<XmlDigestMatcher> digestMatchers = evidenceRecord.getDigestMatchers();

        if (Utils.isCollectionNotEmpty(digestMatchers)) {

            for (XmlDigestMatcher digestMatcher : digestMatchers) {
                // Evidence Records optionally allow additional digests to be present within first data group
                if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != digestMatcher.getType()) {

                    ChainItem<XmlValidationProcessEvidenceRecord> referenceDataFound = referenceDataFound(digestMatcher);
                    if (item == null) {
                        firstItem = item = referenceDataFound;
                    } else {
                        item = item.setNextItem(referenceDataFound);
                    }

                    if (digestMatcher.isDataFound()) {
                        item = item.setNextItem(referenceDataIntact(digestMatcher));
                    }

                }
            }

            ChainItem<XmlValidationProcessEvidenceRecord> atLeastOneDataObjectFound = atLeastOneDataObjectFound(digestMatchers);
            if (item == null) {
                firstItem = item = atLeastOneDataObjectFound;
            } else {
                item = item.setNextItem(atLeastOneDataObjectFound);
            }

            item = item.setNextItem(referenceDataGroup(digestMatchers));

        }

        if (item == null) {
            throw new IllegalStateException("Evidence record shall contain at least one DigestMatcher!");
        }

        // Externally provided evidence records
        if (EvidenceRecordOrigin.EXTERNAL == evidenceRecord.getOrigin() && Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures())) {
            item = item.setNextItem(signedFilesCoveredCheck());
        }

        // ASiC container evidence record
        if (diagnosticData.isContainerInfoPresent() && EvidenceRecordOrigin.CONTAINER == evidenceRecord.getOrigin() &&
                coversSignatureOrTimestampOrEvidenceRecord(evidenceRecord)) {
            item = item.setNextItem(signedAndTimestampedFilesCoveredCheck());
        }

        // Initialize null cryptographic validation
        XmlCryptographicValidation cryptographicValidation = null;

        /*
         * i) Before validating a time-stamp the process shall extract POEs (as per clause 5.6.2.3) of the
         * time-stamp within the next Archive timestamp and initialize the set of temporary POEs with the
         * extracted POEs.
         */
        XmlProofOfExistence lowestPOE = toXmlProofOfExistence(currentTime);

        List<TimestampWrapper> timestampsList = evidenceRecord.getTimestampList();
        if (Utils.isCollectionNotEmpty(timestampsList)) {

            for (TimestampWrapper timestamp : timestampsList) {
                /*
                 * ii) The time stamp validation of the time-stamp token shall be performed, as per clause 5.4.
                 *
                 * iii) The past signature validation process for the signature of the time-stamp token as per clause 5.6.2.4
                 * shall be used with the following inputs: the time-stamp, the TSA's certificate, the X.509 validation
                 * parameters, the X.509 validation constraints, the cryptographic constraints, certificate validation
                 * data, the indication/sub-indication returned in step ii) and the set of POEs available so far, and the
                 * set of temporary POEs.
                 */
                XmlBasicBuildingBlocks bbbTsp = bbbs.get(timestamp.getId());
                XmlValidationProcessArchivalDataTimestamp timestampValidation = getTimestampValidation(timestamp);
                if (bbbTsp != null && timestampValidation != null) {

                    // Basic and Past time-stamp validations are performed inside
                    item = item.setNextItem(timestampValidationConclusive(timestamp, timestampValidation));

                    /*
                     * ETSI TS 119 102-2 (4.3.12.7 Crypto Information Element):
                     *
                     * This element shall be present when the main status indication is INDETERMINATE and
                     * the subindication is CRYPTO_CONSTRAINTS_FAILURE. In all other cases, this element may be present.
                     */
                    XmlConclusion timestampConclusion = timestampValidation.getConclusion();
                    if (Indication.INDETERMINATE == timestampConclusion.getIndication() &&
                            (SubIndication.CRYPTO_CONSTRAINTS_FAILURE == timestampConclusion.getSubIndication() || SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE == timestampConclusion.getSubIndication())) {
                        XmlSAV sav = bbbTsp.getSAV();
                        if ((cryptographicValidation == null || cryptographicValidation.isSecure()) && sav != null) {
                            cryptographicValidation = sav.getCryptographicValidation();
                        }
                    }

                    if (!isValid(timestampValidation)) {
                        result.setConclusion(timestampValidation.getConclusion());
                        break;
                    }
                }
            }

            /*
             * c) If step b) found the ER to be valid, the process shall add a POE for every object covered by the ER at
             * signing time value of the initial archive time-stamp.
             */
            if (result.getConclusion() == null) {
                // when valid, conclusion is not yet set
                lowestPOE = toXmlProofOfExistence(timestampsList.get(0));
            }
        }

        result.setProofOfExistence(lowestPOE);

        // Validate cryptographic constraints of DigestMatchers
        if (Utils.isCollectionNotEmpty(digestMatchers)) {
            CryptographicConstraint cryptographicConstraint = policy.getEvidenceRecordCryptographicConstraint();

            DigestMatcherListCryptographicChainBuilder<XmlValidationProcessEvidenceRecord> digestMatcherCCBuilder =
                    new DigestMatcherListCryptographicChainBuilder<>(i18nProvider, result, digestMatchers, lowestPOE.getTime(), cryptographicConstraint);
            item = digestMatcherCCBuilder.build(item);

            XmlCC failedCC = digestMatcherCCBuilder.getConcernedCC();
            if (failedCC != null && (cryptographicValidation == null || (cryptographicValidation.isSecure() && !isValid(failedCC)))) {
                cryptographicValidation = getCryptographicValidation(failedCC, lowestPOE.getTime());
            }
        }

        result.setCryptographicValidation(cryptographicValidation);

    }

    private ChainItem<XmlValidationProcessEvidenceRecord> referenceDataFound(XmlDigestMatcher digestMatcher) {
        LevelConstraint constraint = policy.getEvidenceRecordDataObjectExistenceConstraint();
        return new ReferenceDataExistenceCheck<>(i18nProvider, result, digestMatcher, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> referenceDataIntact(XmlDigestMatcher digestMatcher) {
        LevelConstraint constraint = policy.getEvidenceRecordDataObjectIntactConstraint();
        return new ReferenceDataIntactCheck<>(i18nProvider, result, digestMatcher, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> atLeastOneDataObjectFound(List<XmlDigestMatcher> digestMatchers) {
        LevelConstraint constraint = policy.getEvidenceRecordDataObjectFoundConstraint();
        return new AtLeastOneReferenceDataObjectFoundCheck<>(i18nProvider, result, digestMatchers, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> referenceDataGroup(List<XmlDigestMatcher> digestMatchers) {
        LevelConstraint constraint = policy.getEvidenceRecordDataObjectGroupConstraint();
        return new ReferenceDataGroupCheck<>(i18nProvider, result, digestMatchers, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> signedFilesCoveredCheck() {
        LevelConstraint constraint = policy.getEvidenceRecordSignedFilesCoveredConstraint();
        return new EvidenceRecordSignedFilesCoveredCheck(i18nProvider, result, evidenceRecord, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> signedAndTimestampedFilesCoveredCheck() {
        LevelConstraint constraint = policy.getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint();
        return new EvidenceRecordSignedAndTimestampedFilesCoveredCheck(i18nProvider, result, diagnosticData.getContainerInfo(), evidenceRecord, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> timestampValidationConclusive(
            TimestampWrapper timestampWrapper, XmlValidationProcessArchivalDataTimestamp timestampValidationResult) {
        return new TimestampValidationCheck<>(i18nProvider, result, timestampWrapper,
                timestampValidationResult, getFailLevelConstraint());
    }

    private XmlValidationProcessArchivalDataTimestamp getTimestampValidation(TimestampWrapper newestTimestamp) {
        for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
            if (Utils.areStringsEqual(xmlTimestamp.getId(), newestTimestamp.getId())) {
                return xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            }
        }
        return null;
    }

    private XmlProofOfExistence toXmlProofOfExistence(Date date) {
        XmlProofOfExistence xmlPoe = new XmlProofOfExistence();
        xmlPoe.setTime(date);
        return xmlPoe;
    }

    private XmlProofOfExistence toXmlProofOfExistence(TimestampWrapper timestampWrapper) {
        XmlProofOfExistence xmlPoe = toXmlProofOfExistence(timestampWrapper.getProductionTime());
        xmlPoe.setTimestampId(timestampWrapper.getId());
        return xmlPoe;
    }

    private XmlCryptographicValidation getCryptographicValidation(XmlCC ccResult, Date validationTime) {
        XmlCryptographicValidation cryptographicValidation = new XmlCryptographicValidation();
        cryptographicValidation.setAlgorithm(ccResult.getVerifiedAlgorithm());
        cryptographicValidation.setNotAfter(ccResult.getNotAfter());
        cryptographicValidation.setSecure(isValid(ccResult));
        cryptographicValidation.setValidationTime(validationTime);
        cryptographicValidation.setConcernedMaterial(evidenceRecord.getId());
        return cryptographicValidation;
    }

    private boolean coversSignatureOrTimestampOrEvidenceRecord(EvidenceRecordWrapper evidenceRecord) {
        return Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures())
                || Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps())
                || Utils.isCollectionNotEmpty(evidenceRecord.getCoveredEvidenceRecords());
    }

}
