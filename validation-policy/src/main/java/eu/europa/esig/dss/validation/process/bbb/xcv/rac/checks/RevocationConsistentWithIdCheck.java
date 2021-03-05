package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Checks consistency of the revocation data, with a difference
 * that provided validating revocation's Id as an additional information
 *
 */
public class RevocationConsistentWithIdCheck extends RevocationConsistentCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param result         the result
     * @param certificate    {@link CertificateWrapper}
     * @param revocationData {@link RevocationWrapper}
     * @param constraint     {@link LevelConstraint}
     */
    public RevocationConsistentWithIdCheck(I18nProvider i18nProvider, XmlConstraintsConclusion result, CertificateWrapper certificate, RevocationWrapper revocationData, LevelConstraint constraint) {
        super(i18nProvider, result, certificate, revocationData, constraint);
    }

    @Override
    protected String getNoThisUpdateMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_NO_THIS_UPDATE_ID, revocationData.getId());
    }

    @Override
    protected String getThisUpdateBeforeCertificateNotBeforeMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_THIS_UPDATE_BEFORE_ID, revocationData.getId(),
                ValidationProcessUtils.getFormattedDate(thisUpdate),
                ValidationProcessUtils.getFormattedDate(certNotBefore),
                ValidationProcessUtils.getFormattedDate(certNotAfter));
    }

    @Override
    protected String getNotAfterAfterCertificateNotAfterMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER_ID, revocationData.getId(),
                ValidationProcessUtils.getFormattedDate(notAfterRevoc),
                ValidationProcessUtils.getFormattedDate(certNotBefore),
                ValidationProcessUtils.getFormattedDate(certNotAfter));
    }

    @Override
    protected String getRevocationIssuerNotFoundMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_ISSUER_NOT_FOUND_ID, revocationData.getId());
    }

    @Override
    protected String getRevocationProducesAtOutOfBoundsMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_PRODUCED_AT_OUT_OF_BOUNDS_ID, revocationData.getId(),
                ValidationProcessUtils.getFormattedDate(producedAt),
                ValidationProcessUtils.getFormattedDate(revocationData.getSigningCertificate().getNotBefore()),
                ValidationProcessUtils.getFormattedDate(revocationData.getSigningCertificate().getNotAfter()));
    }

    @Override
    protected String getRevocationCertHashOkMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CERT_HASH_OK_ID, revocationData.getId());
    }

    @Override
    protected String getRevocationConsistentMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_ID, revocationData.getId(),
                ValidationProcessUtils.getFormattedDate(thisUpdate),
                ValidationProcessUtils.getFormattedDate(certNotBefore),
                ValidationProcessUtils.getFormattedDate(certNotAfter));
    }

}
