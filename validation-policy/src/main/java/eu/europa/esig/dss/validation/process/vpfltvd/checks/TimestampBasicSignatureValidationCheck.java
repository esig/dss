package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

public class TimestampBasicSignatureValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The timestamp to check */
    private final TimestampWrapper timestamp;

    /** Timestamp validation result */
    private final XmlValidationProcessTimestamp timestampValidationResult;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link T}
     * @param timestamp {@link TimestampWrapper}
     * @param timestampValidationResult {@link XmlValidationProcessTimestamp}
     * @param constraint {@link LevelConstraint}
     */
    public TimestampBasicSignatureValidationCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                                  XmlValidationProcessTimestamp timestampValidationResult,
                                                  LevelConstraint constraint) {
        super(i18nProvider, result, constraint, timestamp.getId());
        this.timestamp = timestamp;
        this.timestampValidationResult = timestampValidationResult;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.TST_BBB;
    }

    @Override
    protected boolean process() {
        return isValid(timestampValidationResult);
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION, timestamp.getId(), date);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_IBSVPTC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_IBSVPTC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return timestampValidationResult.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return timestampValidationResult.getConclusion().getSubIndication();
    }

}
