package eu.europa.esig.dss.validation.process.qualification.trust.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TSLTypeEnum;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the Trusted List is defined with MRA
 *
 */
public class TLMRACheck extends ChainItem<XmlTLAnalysis> {

    /** Trusted List to check */
    private final XmlTrustedList currentTL;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlTLAnalysis}
     * @param currentTL {@link XmlTrustedList}
     * @param constraint {@link LevelConstraint}
     */
    public TLMRACheck(I18nProvider i18nProvider, XmlTLAnalysis result, XmlTrustedList currentTL,
                      LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.currentTL = currentTL;
    }

    @Override
    protected boolean process() {
        return currentTL.isMra() == null || !currentTL.isMra();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_TL_IMRA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        XmlTrustedList parentTL = currentTL.getParent();
        if (parentTL != null) {
            String tslType = parentTL.getTSLType();
            if (TSLTypeEnum.EUlistofthelists.getUri().equals(tslType)) {
                return MessageTag.QUAL_TL_IMRA_ANS_V1;
            } else if (TSLTypeEnum.AdESlistofthelists.getUri().equals(tslType)) {
                return MessageTag.QUAL_TL_IMRA_ANS_V2;
            }
        }
        // default
        return MessageTag.QUAL_TL_IMRA_ANS;
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
