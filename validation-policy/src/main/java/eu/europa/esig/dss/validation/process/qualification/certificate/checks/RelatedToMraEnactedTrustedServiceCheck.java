package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * This class verifies whether MRA enacted trusted services are present
 *
 */
public class RelatedToMraEnactedTrustedServiceCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** List of {@code TrustedServiceWrapper}s at control time */
    private final List<TrustedServiceWrapper> trustServicesAtTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param trustServicesAtTime list of {@link TrustedServiceWrapper}s
     * @param constraint {@link LevelConstraint}
     */
    public RelatedToMraEnactedTrustedServiceCheck(I18nProvider i18nProvider, T result,
                                                  List<TrustedServiceWrapper> trustServicesAtTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.trustServicesAtTime = trustServicesAtTime;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionNotEmpty(trustServicesAtTime);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_HAS_METS;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QUAL_HAS_METS_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
