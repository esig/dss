package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies whether a prospective certificate chain with trust anchors valid
 * at validation time has been found
 *
 */
public class ProspectiveCertificateChainAtValidationTimeCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** Validation time to check against */
    private final Date controlTime;

    /** Validation constraint */
    private final LevelConstraint certificateSunsetDateConstraint;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public ProspectiveCertificateChainAtValidationTimeCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                                      CertificateWrapper certificate, Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.controlTime = controlTime;
        this.certificateSunsetDateConstraint = constraint;
    }

    @Override
    protected boolean process() {
        if (ValidationProcessUtils.isTrustAnchor(certificate, controlTime, certificateSunsetDateConstraint)) {
            return true;
        }
        for (CertificateWrapper caCertificate : certificate.getCertificateChain()) {
            if (ValidationProcessUtils.isTrustAnchor(caCertificate, controlTime, certificateSunsetDateConstraint)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_HPCCVVT;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_HPCCVVT_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.CONTROL_TIME_ALONE, controlTime);
    }

}