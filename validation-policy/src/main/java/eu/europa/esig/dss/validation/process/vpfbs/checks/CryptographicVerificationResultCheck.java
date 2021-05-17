package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the format Cryptographic Verification process as per clause 5.2.7 succeeded
 *
 */
public class CryptographicVerificationResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Cryptographic Verification building block suffix */
    private static final String CV_BLOCK_SUFFIX = "-CV";

    /** Cryptographic Verification result */
    private final XmlCV xmlCV;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlCV {@link XmlCV}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public CryptographicVerificationResultCheck(I18nProvider i18nProvider, T result,
                                                XmlCV xmlCV, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + CV_BLOCK_SUFFIX);
        this.xmlCV = xmlCV;
    }

    @Override
    protected boolean process() {
        return xmlCV != null && isValid(xmlCV);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return xmlCV.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return xmlCV.getConclusion().getSubIndication();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_ICVRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_ICVRC_ANS;
    }

}
