/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
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
 * This check verifies whether the signing-certificate is known to not be revoked and revocation data is acceptable
 *
 * @param <T> {@link XmlConstraintsConclusion}
 *
 */
public class CertificateKnownToBeNotRevokedCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /**
     * Certificate to be verified
     */
    private final CertificateWrapper certificate;

    /**
     * Revocation data to be verified
     */
    private final CertificateRevocationWrapper revocationData;

    /**
     * Validation time
     */
    private final Date currentTime;

    /**
     * Conclusion of the Basic Signature Validation block
     */
    private final XmlConclusion bsConclusion;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param certificate {@link CertificateWrapper}
     * @param revocationData {@link CertificateRevocationWrapper}
     * @param currentTime {@link Date}
     * @param bsConclusion {@link XmlConclusion}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateKnownToBeNotRevokedCheck(I18nProvider i18nProvider, T result,
                                               CertificateWrapper certificate, CertificateRevocationWrapper revocationData,
                                               Date currentTime, XmlConclusion bsConclusion, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, certificate.getId());
        this.certificate = certificate;
        this.revocationData = revocationData;
        this.currentTime = currentTime;
        this.bsConclusion = bsConclusion;
    }

    @Override
    protected boolean process() {
        return false;
    }

    private boolean isInValidityRange(CertificateWrapper certificateWrapper) {
        Date notBefore = certificateWrapper.getNotBefore();
        Date notAfter = certificateWrapper.getNotAfter();
        return (notBefore != null && (currentTime.compareTo(notBefore) >= 0)) && (notAfter != null && (currentTime.compareTo(notAfter) <= 0));
    }

    private boolean isRevocationIssuerValid(CertificateWrapper revocationDataIssuer) {
        return revocationDataIssuer.isTrusted() ||
                isInValidityRange(revocationData.getSigningCertificate());
    }

    @Override
    protected String buildAdditionalInfo() {
        if (revocationData != null && !revocationData.isRevoked() && revocationData.getSigningCertificate() != null
                    && !isRevocationIssuerValid(revocationData.getSigningCertificate())) {
            CertificateWrapper revocationIssuer = revocationData.getSigningCertificate();
            String notBeforeStr = revocationIssuer.getNotBefore() == null ? " ? " : ValidationProcessUtils.getFormattedDate(revocationIssuer.getNotBefore());
            String notAfterStr = revocationIssuer.getNotAfter() == null ? " ? " : ValidationProcessUtils.getFormattedDate(revocationIssuer.getNotAfter());
            String validationTime = ValidationProcessUtils.getFormattedDate(currentTime);
            return i18nProvider.getMessage(MessageTag.REVOCATION_CERT_VALIDITY,
                    revocationIssuer.getId(), revocationData.getId(), notBeforeStr, notAfterStr, validationTime);
        }
        return i18nProvider.getMessage(MessageTag.TOKEN_ID, certificate.getId());
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return bsConclusion.getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return bsConclusion.getSubIndication();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.LTV_ISCKNR;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        if (revocationData != null && !revocationData.isRevoked() && revocationData.getSigningCertificate() != null
                && !isRevocationIssuerValid(revocationData.getSigningCertificate())) {
            return MessageTag.LTV_ISCKNR_ANS1;
        }
        return MessageTag.LTV_ISCKNR_ANS0;
    }

}
