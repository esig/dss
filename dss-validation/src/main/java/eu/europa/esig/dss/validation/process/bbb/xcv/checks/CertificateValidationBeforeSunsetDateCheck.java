package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
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
 * This class verifies whether a validation time is before certificate's trust sunset date
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class CertificateValidationBeforeSunsetDateCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

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
    public CertificateValidationBeforeSunsetDateCheck(I18nProvider i18nProvider, T result,
                                                      CertificateWrapper certificate, Date controlTime, LevelConstraint constraint) {
        this(i18nProvider, result, certificate, controlTime, constraint, null);

    }

    /**
     * Constructor with certificate identifier
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     * @param certificateId {@link String} certificate identifier
     */
    protected CertificateValidationBeforeSunsetDateCheck(I18nProvider i18nProvider, T result,
                                                      CertificateWrapper certificate, Date controlTime,
                                                      LevelConstraint constraint, String certificateId) {
        super(i18nProvider, result, constraint, certificateId);
        this.certificate = certificate;
        this.controlTime = controlTime;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.SUB_XCV_TA;
    }

    @Override
    protected boolean process() {
        if (certificate.getTrustSunsetDate() != null) {
            return controlTime.before(certificate.getTrustSunsetDate());
        }
        // if no Sunset date, trust indefinitely
        return certificate.isTrusted();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_IVTBCTSD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_IVTBCTSD_ANS;
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
        if (certificate.getTrustSunsetDate() != null) {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE, ValidationProcessUtils.getFormattedDate(controlTime),
                    ValidationProcessUtils.getFormattedDate(certificate.getTrustSunsetDate()));
        } else {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID);
        }
    }

}