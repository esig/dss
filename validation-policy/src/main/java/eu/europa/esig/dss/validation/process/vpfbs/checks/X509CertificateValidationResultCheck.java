package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the X.509 Certificate Validation as per clause 5.2.6 succeeded
 *
 */
public class X509CertificateValidationResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** X509 Certificate Validation building block suffix */
    private static final String XCV_BLOCK_SUFFIX = "-XCV";

    /** Token's X509CertificateValidation result */
    private final XmlXCV xmlXCV;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlXCV {@link XmlXCV}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public X509CertificateValidationResultCheck(I18nProvider i18nProvider, T result,
                                                XmlXCV xmlXCV, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + XCV_BLOCK_SUFFIX);
        this.xmlXCV = xmlXCV;
    }

    @Override
    protected boolean process() {
        return xmlXCV != null && isValid(xmlXCV);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return xmlXCV.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return xmlXCV.getConclusion().getSubIndication();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_IXCVRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_IXCVRC_ANS;
    }

}
