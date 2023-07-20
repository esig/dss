package eu.europa.esig.dss.validation.process.vpftspwatsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.MessageImprintDigestAlgorithmValidation;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampMessageImprintCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.POE;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.AcceptableBasicTimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;
import eu.europa.esig.dss.validation.process.vpftsp.checks.BasicTimestampValidationCheck;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.MessageImprintDigestAlgorithmValidationCheck;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.PastTimestampValidationCheck;

import java.util.Date;
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
     * @param vpftsp {@link XmlValidationProcessBasicTimestamp}
     * @param timestamp {@link TimestampWrapper}
     * @param bbbs map of BasicBuildingBlocks
     * @param policy {@link ValidationPolicy}
     * @param poe {@link POEExtraction}
     */
    public ValidationProcessForTimestampsWithArchivalData(final I18nProvider i18nProvider, final TimestampWrapper timestamp,
            final XmlValidationProcessBasicTimestamp vpftsp, final Map<String, XmlBasicBuildingBlocks> bbbs,
            final Date currentTime, final ValidationPolicy policy, final POEExtraction poe) {
        super(i18nProvider, new XmlValidationProcessArchivalDataTimestamp());
        this.vpftsp = vpftsp;
        this.timestamp = timestamp;
        this.bbbs = bbbs;
        this.currentTime = currentTime;
        this.policy = policy;
        this.poe = poe;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPFSWATSP;
    }

    @Override
    protected void initChain() {
        XmlProofOfExistence lowestPOE = getLowestPOE();
        Date lowestPOETime = lowestPOE.getTime();
        result.setProofOfExistence(lowestPOE);

        XmlConclusion basicTimestampConclusion = vpftsp.getConclusion();

        ChainItem<XmlValidationProcessArchivalDataTimestamp> item = firstItem = timestampBasicSignatureValidationAcceptable(timestamp, vpftsp);

        if (ValidationProcessUtils.isAllowedBasicTimestampValidation(basicTimestampConclusion)) {

            item = item.setNextItem(timestampBasicSignatureValidationConclusive(timestamp, vpftsp));

            MessageImprintDigestAlgorithmValidation midav = timestampDigestAlgorithmValidation(timestamp, lowestPOETime);
            XmlSAV davResult = midav.execute();

            /*
             * b) If PASSED is returned and the cryptographic hash function used in the time-stamp
             * (messageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp,
             * the long term validation process shall perform the POE extraction process with the signature, the
             * time-stamp and the cryptographic constraints as inputs. The long term validation process shall
             * add the returned POEs to the set of POEs.
             */
            if (isValid(vpftsp)) {

                item = item.setNextItem(messageImprintDigestAlgorithm(timestamp, davResult, lowestPOETime));

                if (isValid(davResult)) {

                    item = item.setNextItem(timestampMessageImprint(timestamp));

                    poe.extractPOE(timestamp);

                }
            }
            /*
             * c) If the output of the validation is INDETERMINATE/REVOKED_NO_POE,
             * INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE or
             * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, the SVA shall perform past
             * signature validation process (as per clause 5.6.2.4) with the following inputs: the time-stamp, the
             * indication/sub-indication returned by the time-stamp validation process in step 5a, the TSA's certificate,
             * the X.509 validation parameters, X.509 validation constraints, cryptographic constraints, certificate
             * validation data and the set of POEs.
             */
            else {
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

                    item = item.setNextItem(messageImprintDigestAlgorithm(timestamp, davResult, lowestPOETime));

                    if (isValid(davResult)) {

                        item = item.setNextItem(timestampMessageImprint(timestamp));

                        poe.extractPOE(timestamp);

                    }
                }
            }
        }

    }

    private XmlProofOfExistence getLowestPOE() {
        POE lowestPOE = poe.getLowestPOE(timestamp.getId());
        XmlProofOfExistence poe = new XmlProofOfExistence();
        poe.setTime(lowestPOE.getTime());
        return poe;
    }

    private ChainItem<XmlValidationProcessArchivalDataTimestamp> timestampBasicSignatureValidationAcceptable(
            TimestampWrapper timestampWrapper, XmlValidationProcessBasicTimestamp timestampValidationResult) {
        return new AcceptableBasicTimestampValidationCheck<>(i18nProvider, result, timestampWrapper,
                timestampValidationResult, getFailLevelConstraint());
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
