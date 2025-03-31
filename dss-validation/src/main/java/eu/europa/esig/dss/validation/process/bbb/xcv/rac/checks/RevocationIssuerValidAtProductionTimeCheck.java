package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Verifies whether the revocation's issuer certificate has been valid at the revocation's production time
 *
 */
public class RevocationIssuerValidAtProductionTimeCheck extends ChainItem<XmlRAC> {

    /** Revocation data to check */
    private final RevocationWrapper revocationData;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlRAC}
     * @param revocationData {@link RevocationWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public RevocationIssuerValidAtProductionTimeCheck(I18nProvider i18nProvider, XmlRAC result,
                                                      RevocationWrapper revocationData, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.revocationData = revocationData;
    }

    @Override
    protected boolean process() {
        // check performed only for OCSP certificates
        return !RevocationType.OCSP.equals(revocationData.getRevocationType()) ||
                checkOCSPResponderValidAtRevocationProductionTime();
    }

    private boolean checkOCSPResponderValidAtRevocationProductionTime() {
        CertificateWrapper revocationIssuer = revocationData.getSigningCertificate();
        Date producedAt = revocationData.getProductionDate();
        return revocationIssuer != null &&
                producedAt.compareTo(revocationIssuer.getNotBefore()) >= 0 &&
                producedAt.compareTo(revocationIssuer.getNotAfter()) <= 0;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (revocationData.getSigningCertificate() != null) {
            MessageTag messageTag;
            if (process()) {
                messageTag = MessageTag.REVOCATION_PRODUCED_AT_CERT_VALIDITY;
            } else {
                messageTag = MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS;
            }
            return i18nProvider.getMessage(messageTag,
                    ValidationProcessUtils.getFormattedDate(revocationData.getProductionDate()),
                    ValidationProcessUtils.getFormattedDate(revocationData.getSigningCertificate().getNotBefore()),
                    ValidationProcessUtils.getFormattedDate(revocationData.getSigningCertificate().getNotAfter()));
        }
        return null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_REVOC_ISSUER_VALID_AT_PROD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_REVOC_ISSUER_VALID_AT_PROD_ANS;
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
