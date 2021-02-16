package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the QCEuRetentionPeriod constraint
 */
public class CertificateMinQcEuRetentionPeriodCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** The constraint from policy file */
    private final IntValueConstraint constraint;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link IntValueConstraint}
     */
    public CertificateMinQcEuRetentionPeriodCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                                  CertificateWrapper certificate, IntValueConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.constraint = constraint;
    }

    @Override
    protected boolean process() {
        Integer qcEuRetentionPeriod = certificate.getQCEuRetentionPeriod();
        if (qcEuRetentionPeriod != null) {
            return qcEuRetentionPeriod >= constraint.getValue();
        }
        // not present
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCERPA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCERPA_ANS;
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
