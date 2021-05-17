package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Collection;
import java.util.List;

/**
 * Checks if a collection of content timestamps is not empty
 */
public class ContentTimestampsCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The content timestamps collection */
    private final Collection<TimestampWrapper> contentTimestamps;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param contentTimestamps a collection of {@link TimestampWrapper}s
     * @param constraint {@link LevelConstraint}
     */
    public ContentTimestampsCheck(I18nProvider i18nProvider, T result,
                                  List<TimestampWrapper> contentTimestamps, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.contentTimestamps = contentTimestamps;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionNotEmpty(contentTimestamps);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return null;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_ISCCTC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_ISCCTC_ANS;
    }

}
