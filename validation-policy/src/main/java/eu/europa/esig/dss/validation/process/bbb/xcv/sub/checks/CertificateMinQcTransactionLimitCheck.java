package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.QCLimitValueWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks the minimal allowed QC transaction limit for the certificate
 */
public class CertificateMinQcTransactionLimitCheck extends ChainItem<XmlSubXCV> {

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
    public CertificateMinQcTransactionLimitCheck(I18nProvider i18nProvider, XmlSubXCV result,
                                                 CertificateWrapper certificate, IntValueConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.constraint = constraint;
    }

    @Override
    protected boolean process() {
        QCLimitValueWrapper qcLimitValue = certificate.getQCLimitValue();
        if (qcLimitValue != null) {
            /*
             * EN 319 412-5 (ch. 4.3.2 QCStatement regarding limits on the value of transactions) :
             *
             * -- value = amount * 10^exponent
             */
            double value = qcLimitValue.getAmount() * Math.pow(10, qcLimitValue.getExponent());
            return value >= constraint.getValue();
        }
        // not present
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCLVA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCLVA_ANS;
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
