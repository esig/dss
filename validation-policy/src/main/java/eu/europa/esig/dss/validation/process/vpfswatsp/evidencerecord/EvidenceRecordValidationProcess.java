package eu.europa.esig.dss.validation.process.vpfswatsp.evidencerecord;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.validation.process.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestMatcherCryptographicCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.TimestampValidationCheck;

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
     * @param evidenceRecord {@link EvidenceRecordWrapper} to be validated
     * @param xmlTimestamps a collection of {@link XmlTimestamp} validations
     * @param bbbs a map of performed {@link XmlBasicBuildingBlocks}s
     * @param validationPolicy {@link ValidationPolicy} to be used
     * @param currentTime {@link Date} validation time
     */
    public EvidenceRecordValidationProcess(I18nProvider i18nProvider, EvidenceRecordWrapper evidenceRecord,
                                           Collection<XmlTimestamp> xmlTimestamps, Map<String, XmlBasicBuildingBlocks> bbbs,
                                           ValidationPolicy validationPolicy, Date currentTime) {
        super(i18nProvider, new XmlValidationProcessEvidenceRecord());

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

                ChainItem<XmlValidationProcessEvidenceRecord> referenceDataFound = referenceDataFound(digestMatcher);
                if (item == null) {
                    firstItem = item = referenceDataFound;
                } else {
                    item = item.setNextItem(referenceDataFound);
                }

                item = item.setNextItem(referenceDataIntact(digestMatcher));

            }

        }

        if (item == null) {
            throw new IllegalStateException("Evidence record shall contain at least one DigestMatcher!");
        }

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

                }

                if (!isValid(timestampValidation)) {
                    result.setConclusion(timestampValidation.getConclusion());
                    break;
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

            for (XmlDigestMatcher digestMatcher : digestMatchers) {

                item = item.setNextItem(digestMatcherIsSecureAtPoeTime(digestMatcher, lowestPOE.getTime(), cryptographicConstraint));

            }

        }

    }

    private ChainItem<XmlValidationProcessEvidenceRecord> referenceDataFound(XmlDigestMatcher digestMatcher) {
        LevelConstraint constraint = policy.getEvidenceRecordDataObjectExistenceConstraint();
        return new ReferenceDataExistenceCheck<>(i18nProvider, result, digestMatcher, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> referenceDataIntact(XmlDigestMatcher digestMatcher) {
        LevelConstraint constraint = policy.getEvidenceRecordDataObjectIntactConstraint();
        return new ReferenceDataIntactCheck<>(i18nProvider, result, digestMatcher, constraint);
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> timestampValidationConclusive(
            TimestampWrapper timestampWrapper, XmlValidationProcessArchivalDataTimestamp timestampValidationResult) {
        return new TimestampValidationCheck<>(i18nProvider, result, timestampWrapper,
                timestampValidationResult, getFailLevelConstraint());
    }

    private ChainItem<XmlValidationProcessEvidenceRecord> digestMatcherIsSecureAtPoeTime(XmlDigestMatcher digestMatcher, Date validationDate,
                                                             CryptographicConstraint constraint) {
        MessageTag position = ValidationProcessUtils.getDigestMatcherCryptoPosition(digestMatcher);
        return new DigestMatcherCryptographicCheck<>(i18nProvider, digestMatcher.getDigestMethod(), result, validationDate, position, constraint);
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

}
