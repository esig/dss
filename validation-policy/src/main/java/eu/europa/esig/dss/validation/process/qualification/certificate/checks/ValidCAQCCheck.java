package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if an acceptable Trust Service for a qualified certificate issuance found
 *
 */
public class ValidCAQCCheck extends ChainItem<XmlValidationCertificateQualification> {

    /** {@code TrustedServiceWrapper} */
    private final TrustedServiceWrapper trustService;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationCertificateQualification}
     * @param trustService {@link TrustedServiceWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public ValidCAQCCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result,
                          TrustedServiceWrapper trustService, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.trustService = trustService;
    }

    @Override
    protected boolean process() {
        return trustService != null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_HAS_VALID_CAQC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QUAL_HAS_VALID_CAQC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
