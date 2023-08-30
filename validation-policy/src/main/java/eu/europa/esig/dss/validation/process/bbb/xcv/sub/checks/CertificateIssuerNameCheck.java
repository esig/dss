package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies if the certificate's issuer distinguished name matches 
 * the subject distinguished name of the issuer
 * 
 */
public class CertificateIssuerNameCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateIssuerNameCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate, 
                                      LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        CertificateWrapper issuerCertificate;
        if (certificate.isSelfSigned()) {
            issuerCertificate = certificate;
        } else {
            issuerCertificate = certificate.getSigningCertificate();
        }
        if (issuerCertificate != null) {
            return certificate.getCertificateIssuerDN().equals(issuerCertificate.getCertificateDN());
        }
        // true if no issuer found
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_DCIDNMSDNIC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_DCIDNMSDNIC_ANS;
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
