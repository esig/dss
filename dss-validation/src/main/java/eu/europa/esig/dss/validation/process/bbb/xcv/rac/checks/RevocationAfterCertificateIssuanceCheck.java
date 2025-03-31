package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks whether the concerned certificate has existed at the time of revocation data generation
 *
 */
public class RevocationAfterCertificateIssuanceCheck extends ChainItem<XmlRAC> {

    /** The certificate in question */
    private final CertificateWrapper certificate;

    /** Revocation data to check */
    private final RevocationWrapper revocationData;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlRAC}
     * @param certificate {@link CertificateWrapper}
     * @param revocationData {@link RevocationWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public RevocationAfterCertificateIssuanceCheck(I18nProvider i18nProvider, XmlRAC result, CertificateWrapper certificate,
                                                   RevocationWrapper revocationData, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.revocationData = revocationData;
    }

    @Override
    protected boolean process() {
        Date certNotBefore = certificate.getNotBefore();
        Date thisUpdate = revocationData.getThisUpdate();
        return certNotBefore != null && thisUpdate != null && certNotBefore.compareTo(thisUpdate) <= 0;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_INFO,
                ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_REVOC_AFTER_CERT_NOT_BEFORE;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_REVOC_AFTER_CERT_NOT_BEFORE_ANS;
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
