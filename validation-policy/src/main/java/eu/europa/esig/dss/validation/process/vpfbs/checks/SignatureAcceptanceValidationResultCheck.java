package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the format Signature Acceptance Validation process as per clause 5.2.8 succeeded
 *
 */
public class SignatureAcceptanceValidationResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Signature Acceptance Validation building block suffix */
    private static final String SAV_BLOCK_SUFFIX = "-SAV";

    /** Signature Acceptance Validation result */
    private final XmlSAV xmlSAV;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlSAV {@link XmlSAV}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public SignatureAcceptanceValidationResultCheck(I18nProvider i18nProvider, T result,
                                                    XmlSAV xmlSAV, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + SAV_BLOCK_SUFFIX);
        this.xmlSAV = xmlSAV;
    }

    @Override
    protected boolean process() {
        return xmlSAV != null && isValid(xmlSAV);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return xmlSAV.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return xmlSAV.getConclusion().getSubIndication();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_ISAVRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_ISAVRC_ANS;
    }

}
