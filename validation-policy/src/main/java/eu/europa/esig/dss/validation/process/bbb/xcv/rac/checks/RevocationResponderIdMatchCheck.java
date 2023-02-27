package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * This method verifies whether the ResponderId property of an OCSP response matches
 * the found certificate used to sign the OCSP response.
 *
 */
public class RevocationResponderIdMatchCheck extends ChainItem<XmlRAC> {

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
    public RevocationResponderIdMatchCheck(I18nProvider i18nProvider, XmlRAC result, RevocationWrapper revocationData,
                                           LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.revocationData = revocationData;
    }

    @Override
    protected boolean process() {
        // ResponderId is returned as a SIGNING_CERTIFICATE for OCSP token
        List<RelatedCertificateWrapper> relatedSigningCertificates = revocationData.foundCertificates()
                .getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        CertificateWrapper signingCertificate = revocationData.getSigningCertificate();
        if (Utils.collectionSize(relatedSigningCertificates) == 1 && signingCertificate != null) {
            return relatedSigningCertificates.iterator().next().getId().equals(signingCertificate.getId());
        }
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_REVOC_RESPID_MATCH;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_REVOC_RESPID_MATCH_ANS;
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
