package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * Checks if at least one covered data object has been found
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class AtLeastOneReferenceDataObjectFoundCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The collection of DigestMatchers */
    private final List<XmlDigestMatcher> digestMatchers;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param digestMatchers a list of {@link XmlDigestMatcher}s
     * @param constraint {@link LevelConstraint}
     */
    public AtLeastOneReferenceDataObjectFoundCheck(I18nProvider i18nProvider, T result,
                                                   List<XmlDigestMatcher> digestMatchers, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.digestMatchers = digestMatchers;
    }

    @Override
    protected boolean process() {
        return digestMatchers.stream().anyMatch(XmlDigestMatcher::isDataFound);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_CV_ER_IODOF;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_CV_ER_IODOF_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIGNED_DATA_NOT_FOUND;
    }

}
