package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.ArrayList;
import java.util.List;

/**
 * This class verifies if the certificate does not contain forbidden certificate extensions
 *
 */
public class CertificateForbiddenExtensionsCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link MultiValuesConstraint}
     */
    public CertificateForbiddenExtensionsCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                               CertificateWrapper certificate, MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionEmpty(getUsedForbiddenCertificateExtensionsOids());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_DCCFCE;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_DCCFCE_ANS;
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return buildXmlMessage(getErrorMessageTag(), getUsedForbiddenCertificateExtensionsOids());
    }

    private List<String> getUsedForbiddenCertificateExtensionsOids() {
        List<String> values = new ArrayList<>();
        for (XmlCertificateExtension certificateExtension : certificate.getCertificateExtensions()) {
            if (processValueCheck(certificateExtension.getOID())) {
                values.add(certificateExtension.getOID());
            }
        }
        return values;
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
