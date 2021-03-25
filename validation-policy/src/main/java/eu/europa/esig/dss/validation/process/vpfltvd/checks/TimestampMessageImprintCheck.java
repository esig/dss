package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks message-imprint validity for a timestamp token
 */
public abstract class TimestampMessageImprintCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The timestamp to check */
    protected final TimestampWrapper timestamp;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param timestamp {@link TimestampWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public TimestampMessageImprintCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                 LevelConstraint constraint) {
        super(i18nProvider, result, constraint, timestamp.getId());
        this.timestamp = timestamp;
    }

    @Override
    protected boolean process() {
        return timestamp.isMessageImprintDataFound() && timestamp.isMessageImprintDataIntact();
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
