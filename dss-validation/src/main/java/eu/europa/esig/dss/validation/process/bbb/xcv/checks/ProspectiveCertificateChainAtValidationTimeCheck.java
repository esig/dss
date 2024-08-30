package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies whether a prospective certificate chain with trust anchors valid
 * at validation time has been found
 *
 */
public class ProspectiveCertificateChainAtValidationTimeCheck extends ChainItem<XmlXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** Validation time to check against */
    private final Date controlTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public ProspectiveCertificateChainAtValidationTimeCheck(I18nProvider i18nProvider, XmlXCV result,
                                                      CertificateWrapper certificate, Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.controlTime = controlTime;
    }

    @Override
    protected boolean process() {
        // FAIL level constraint is used to fail the check
        if (ValidationProcessUtils.isTrustAnchor(certificate, controlTime, getFailLevelConstraint())) {
            return true;
        }
        for (CertificateWrapper caCertificate : certificate.getCertificateChain()) {
            if (ValidationProcessUtils.isTrustAnchor(caCertificate, controlTime, getFailLevelConstraint())) {
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

    private LevelConstraint getFailLevelConstraint() {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        return constraint;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.VALIDATION_TIME, ValidationProcessUtils.getFormattedDate(controlTime));
    }

}