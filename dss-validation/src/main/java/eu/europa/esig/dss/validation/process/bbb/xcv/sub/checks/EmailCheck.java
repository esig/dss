package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

/**
 * Checks if the certificate's email attribute is acceptable
 */
public class EmailCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSubXCV}
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link MultiValuesConstraint}
     */
    public EmailCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                      MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        return processValueCheck(certificate.getEmail());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_ISCGEMAIL;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_ISCGEMAIL_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
    }

}
