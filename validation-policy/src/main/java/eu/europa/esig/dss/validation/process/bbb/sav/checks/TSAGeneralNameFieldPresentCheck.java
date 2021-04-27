package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the TSTInfo.tsa field is present
 */
public class TSAGeneralNameFieldPresentCheck extends ChainItem<XmlSAV> {

    /**
     * Timestamp to verify
     */
    private final TimestampWrapper timestampWrapper;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param timestampWrapper {@link TimestampWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public TSAGeneralNameFieldPresentCheck(I18nProvider i18nProvider, XmlSAV result, TimestampWrapper timestampWrapper,
                                           LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.timestampWrapper = timestampWrapper;
    }

    @Override
    protected boolean process() {
        return timestampWrapper.isTSAGeneralNamePresent();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_TAV_ITSAP;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_TAV_ITSAP_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIG_CONSTRAINTS_FAILURE;
    }

}
