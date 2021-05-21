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
 * Verifies if the result if X509CertificateValidation is not indication INDETERMINATE with the sub-indication
 * OUT_OF_BOUNDS_NO_POE or OUT_OF_BOUNDS_NOT_REVOKED
 *
 */
public class ValidationTimeAtCertificateValidityRangeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

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
    public ValidationTimeAtCertificateValidityRangeCheck(I18nProvider i18nProvider, T result,
                                                         XmlXCV xmlXCV, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + XCV_BLOCK_SUFFIX);
        this.xmlXCV = xmlXCV;
    }

    @Override
    protected boolean process() {
        return xmlXCV != null && !(Indication.INDETERMINATE.equals(xmlXCV.getConclusion().getIndication()) &&
                (SubIndication.OUT_OF_BOUNDS_NO_POE.equals(xmlXCV.getConclusion().getSubIndication()) ||
                        SubIndication.OUT_OF_BOUNDS_NOT_REVOKED.equals(xmlXCV.getConclusion().getSubIndication())));
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
        return MessageTag.BSV_IVTAVRSC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_IVTAVRSC_ANS;
    }

}
