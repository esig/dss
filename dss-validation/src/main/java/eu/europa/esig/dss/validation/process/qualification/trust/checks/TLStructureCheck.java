package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValueRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether structure of Trusted List is valid
 *
 */
public class TLStructureCheck extends ChainItem<XmlTLAnalysis> {

    /** Trusted List to check */
    private final XmlTrustedList currentTL;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlTLAnalysis}
     * @param currentTl {@link XmlTrustedList}
     * @param constraint {@link ValueRule}
     */
    public TLStructureCheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTl,
                             LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.currentTL = currentTl;
    }

    @Override
    protected boolean process() {
        return currentTL.getStructuralValidation() == null || Utils.isTrue(currentTL.getStructuralValidation().isValid());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_TL_SV;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QUAL_TL_SV_ANS;
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
