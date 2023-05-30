package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.List;

/**
 * Checks if a corresponding Trust Service found valid at control time
 *
 */
public class TrustServiceAtTimeCheck extends ChainItem<XmlValidationCertificateQualification> {

    /** List of {@code TrustedServiceWrapper}s at control time */
    private final List<TrustedServiceWrapper> trustServicesAtTime;

    /** The validation time type */
    private final ValidationTime validationTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationCertificateQualification}
     * @param trustServicesAtTime list of {@link TrustedServiceWrapper}s
     * @param validationTime {@link ValidationTime}
     * @param constraint {@link LevelConstraint}
     */
    public TrustServiceAtTimeCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result,
                     List<TrustedServiceWrapper> trustServicesAtTime, ValidationTime validationTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.trustServicesAtTime = trustServicesAtTime;
        this.validationTime = validationTime;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionNotEmpty(trustServicesAtTime);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_HAS_ATTIME;
    }

    @Override
    protected XmlMessage buildConstraintMessage() {
        return buildXmlMessage(getMessageTag(), ValidationProcessUtils.getValidationTimeMessageTag(validationTime));
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QUAL_HAS_ATTIME_ANS;
    }

    @Override
    protected XmlMessage buildErrorMessage() {
        return buildXmlMessage(getErrorMessageTag(), ValidationProcessUtils.getValidationTimeMessageTag(validationTime));
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
