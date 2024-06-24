package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractCertificateCheckItem;

/**
 * This class is used to verify whether the revocation data check shall be skipped for the given certificate
 *
 */
public class RevocationDataRequiredCheck<T extends XmlConstraintsConclusion> extends AbstractCertificateCheckItem<T> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public RevocationDataRequiredCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate,
                                       CertificateValuesConstraint constraint) {
        super(i18nProvider, result, certificate, constraint);
        this.certificate = certificate;
    }

    @Override
    public boolean process() {
        return !certificate.isTrusted() && !certificate.isSelfSigned() && !processCertificateCheck(certificate);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_IRDCSFC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_IRDCSFC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
    }

}
