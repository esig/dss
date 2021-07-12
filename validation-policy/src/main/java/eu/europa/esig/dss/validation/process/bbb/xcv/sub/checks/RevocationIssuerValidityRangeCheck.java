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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
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
 * This class verifies if a validation time is in the validity range of the certificate of the issuer of
 * the revocation information
 *
 */
public class RevocationIssuerValidityRangeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Validation date */
    private final Date currentTime;

    /** The revocation data to verify issuer of */
    private final RevocationWrapper revocationWrapper;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param revocationWrapper {@link RevocationWrapper}
     * @param currentTime {@link Date} validation time
     * @param constraint {@link LevelConstraint}
     */
    public RevocationIssuerValidityRangeCheck(I18nProvider i18nProvider, T result, RevocationWrapper revocationWrapper,
                                              Date currentTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.currentTime = currentTime;
        this.revocationWrapper = revocationWrapper;
    }

    @Override
    protected boolean process() {
        CertificateWrapper signingCertificate = revocationWrapper.getSigningCertificate();
        if (signingCertificate != null) {
            Date notBefore = signingCertificate.getNotBefore();
            Date notAfter = signingCertificate.getNotAfter();
            return (notBefore != null && (currentTime.compareTo(notBefore) >= 0)) && (notAfter != null && (currentTime.compareTo(notAfter) <= 0));
        }
        return false;
    }

    @Override
    protected String buildAdditionalInfo() {
        CertificateWrapper certificate = revocationWrapper.getSigningCertificate();
        if (certificate != null) {
            String notBeforeStr = certificate.getNotBefore() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificate.getNotBefore());
            String notAfterStr = certificate.getNotAfter() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificate.getNotAfter());
            String validationTime = ValidationProcessUtils.getFormattedDate(currentTime);
            return i18nProvider.getMessage(MessageTag.REVOCATION_CERT_VALIDITY,
                    certificate.getId(), revocationWrapper.getId(), notBeforeStr, notAfterStr, validationTime);
        }
        return null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_ICTIVRCIRI;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_ICTIVRCIRI_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE;
    }

}
