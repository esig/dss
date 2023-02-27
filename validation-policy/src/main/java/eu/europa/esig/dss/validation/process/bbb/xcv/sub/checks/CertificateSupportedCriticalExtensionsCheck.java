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
 * Verifies if the certificate does not contain any of the certificate extensions listed within
 * a list of unsupported certificate extensions
 *
 */
public class CertificateSupportedCriticalExtensionsCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

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
    public CertificateSupportedCriticalExtensionsCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                               CertificateWrapper certificate, MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionEmpty(getUnsupportedCertificateExtensionsOids());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_DCCUCE;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_DCCUCE_ANS;
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return buildXmlMessage(getErrorMessageTag(), getUnsupportedCertificateExtensionsOids());
    }

    private List<String> getUnsupportedCertificateExtensionsOids() {
        List<String> values = new ArrayList<>();
        for (XmlCertificateExtension certificateExtension : certificate.getCertificateExtensions()) {
            if (certificateExtension.isCritical() && !processValueCheck(certificateExtension.getOID())) {
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
