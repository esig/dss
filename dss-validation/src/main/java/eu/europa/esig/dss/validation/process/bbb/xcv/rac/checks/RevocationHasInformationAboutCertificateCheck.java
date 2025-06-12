/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Checks whether the concerned certificate has existed at the time of revocation data generation
 *
 */
public class RevocationHasInformationAboutCertificateCheck extends ChainItem<XmlRAC> {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationHasInformationAboutCertificateCheck.class);

    /** The certificate in question */
    private final CertificateWrapper certificate;

    /** Revocation data to check */
    private final RevocationWrapper revocationData;

    /** Defines date after which the revocation issuer ensure the revocation is contained for the certificate */
    private Date notAfterRevoc;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlRAC}
     * @param certificate {@link CertificateWrapper}
     * @param revocationData {@link RevocationWrapper}
     * @param constraint {@link LevelRule}
     */
    public RevocationHasInformationAboutCertificateCheck(I18nProvider i18nProvider, XmlRAC result, CertificateWrapper certificate,
                                                         RevocationWrapper revocationData, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.revocationData = revocationData;
    }

    @Override
    protected boolean process() {
        return checkCertHashMatches() || checkIssuerHasInformationForExpiredCertificate();
    }

    private boolean checkIssuerHasInformationForExpiredCertificate() {
        Date certNotAfter = certificate.getNotAfter();
        Date revocationIssuerKnowsCertStatusSince = getNotAfterRevoc();
        return certNotAfter != null && revocationIssuerKnowsCertStatusSince != null
                && certNotAfter.compareTo(revocationIssuerKnowsCertStatusSince) >= 0;
    }

    private boolean checkCertHashMatches() {
        /*
         * certHash extension can be present in an OCSP Response. If present, a digest match indicates the OCSP
         * responder knows the certificate as we have it, and so also its revocation state
         */
        return revocationData.isCertHashExtensionPresent() && revocationData.isCertHashExtensionMatch();
    }

    private Date getNotAfterRevoc() {
        if (notAfterRevoc == null) {
            notAfterRevoc = revocationData.getThisUpdate();

            /*
             * If a CRL contains the extension expiredCertsOnCRL defined in [i.12], it shall prevail over the TL
             * extension value but only for that specific CRL.
             */
            Date expiredCertsOnCRL = revocationData.getExpiredCertsOnCRL();
            if (expiredCertsOnCRL != null) {
                if (expiredCertsOnCRL.before(notAfterRevoc)) {
                    notAfterRevoc = expiredCertsOnCRL;
                } else {
                    LOG.info("ExpiredCertsOnCRL : '{}' is not before revocation's thisUpdate : '{}'.",
                            ValidationProcessUtils.getFormattedDate(expiredCertsOnCRL), ValidationProcessUtils.getFormattedDate(notAfterRevoc));
                }
            }

            /*
             * If an OCSP response contains the extension ArchiveCutoff defined in section 4.4.4 of
             * IETF RFC 6960 [i.11], it shall prevail over the TL extension value but only for that specific OCSP
             * response.
             */
            Date archiveCutOff = revocationData.getArchiveCutOff();
            if (archiveCutOff != null) {
                if (archiveCutOff.before(notAfterRevoc)) {
                    notAfterRevoc = archiveCutOff;
                } else {
                    LOG.info("ArchiveCutoff : '{}' is not before revocation's thisUpdate : '{}'.",
                            ValidationProcessUtils.getFormattedDate(archiveCutOff), ValidationProcessUtils.getFormattedDate(notAfterRevoc));
                }
            }

            /* expiredCertsRevocationInfo Extension from TL */
            if (expiredCertsOnCRL == null && archiveCutOff == null) {
                Date expiredCertsRevocationInfo = getExpiredCertsRevocationInfo(revocationData);
                if (expiredCertsRevocationInfo != null) {
                    if (expiredCertsRevocationInfo.before(notAfterRevoc)) {
                        notAfterRevoc = expiredCertsRevocationInfo;
                    } else {
                        LOG.info("ExpiredCertsRevocationInfo : '{}' is not before revocation's thisUpdate : '{}'.",
                                ValidationProcessUtils.getFormattedDate(expiredCertsRevocationInfo), ValidationProcessUtils.getFormattedDate(notAfterRevoc));
                    }
                }
            }
        }
        return notAfterRevoc;
    }

    private Date getExpiredCertsRevocationInfo(RevocationWrapper revocationData) {
        CertificateWrapper revocCert = revocationData.getSigningCertificate();
        if (revocCert != null) {
            return revocCert.getCertificateTSPServiceExpiredCertsRevocationInfo();
        }
        return null;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (!process()) {
            return getNotAfterAfterCertificateNotAfterMessage();

        } else if (checkRevocationThisUpdateIsInCertificateValidityRange()) {
            return getRevocationConsistentMessage();

        } else if (checkCertHashMatches()) {
            return getRevocationCertHashOkMessage();

        } else if (checkExpiredCertsOnCRLPresent()) {
            return getRevocationConsistentWithExpiredCertsOnCRLMessage();

        } else if (checkArchiveCutOffPresent()) {
            return getRevocationConsistentWithArchiveCutoffMessage();

        } else if (checkExpiredCertsRevocationInfoPresent()) {
            return getRevocationConsistentWithExpiredCertsRevocationInfoMessage();

        } else {
            return getRevocationInfoMessage();
        }
    }

    private boolean checkRevocationThisUpdateIsInCertificateValidityRange() {
        return revocationData.getThisUpdate().compareTo(certificate.getNotBefore()) >= 0 &&
                revocationData.getThisUpdate().compareTo(certificate.getNotAfter()) <= 0;
    }

    private boolean checkExpiredCertsOnCRLPresent() {
        return revocationData.getExpiredCertsOnCRL() != null;
    }

    private boolean checkArchiveCutOffPresent() {
        return revocationData.getArchiveCutOff() != null;
    }

    private boolean checkExpiredCertsRevocationInfoPresent() {
        return getExpiredCertsRevocationInfo(revocationData) != null;
    }

    /**
     * Returns the additional information message in case if
     * computed time 'notAfter' is after the certificate's notAfter
     *
     * @return {@link String}
     */
    protected String getNotAfterAfterCertificateNotAfterMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER,
                ValidationProcessUtils.getFormattedDate(notAfterRevoc),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    /**
     * Returns the additional information message when the revocation is consistent
     *
     * @return {@link String}
     */
    private String getRevocationConsistentMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT,
                ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    /**
     * Returns the additional information message when certHash matches
     *
     * @return {@link String}
     */
    private String getRevocationCertHashOkMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CERT_HASH_OK);
    }

    /**
     * Returns the additional information message when the revocation is consistent with expiredCertsOnCRL
     *
     * @return {@link String}
     */
    private String getRevocationConsistentWithExpiredCertsOnCRLMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_CRL,
                ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(revocationData.getExpiredCertsOnCRL()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    /**
     * Returns the additional information message when the revocation is consistent with archiveCutoff
     *
     * @return {@link String}
     */
    private String getRevocationConsistentWithArchiveCutoffMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_OCSP,
                ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(revocationData.getArchiveCutOff()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    /**
     * Returns the additional information message when the revocation is consistent with archiveCutoff
     *
     * @return {@link String}
     */
    private String getRevocationConsistentWithExpiredCertsRevocationInfoMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT_TL,
                ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(getExpiredCertsRevocationInfo(revocationData)),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    /**
     * Returns the additional information message for revocation data in case of other events
     *
     * @return {@link String}
     */
    private String getRevocationInfoMessage() {
        return i18nProvider.getMessage(MessageTag.REVOCATION_INFO,
                ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotBefore()),
                ValidationProcessUtils.getFormattedDate(certificate.getNotAfter()));
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_REVOC_HAS_CERT_INFO_ANS;
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
