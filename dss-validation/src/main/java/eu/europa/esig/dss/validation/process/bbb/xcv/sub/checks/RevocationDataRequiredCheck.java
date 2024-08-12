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
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractCertificateCheckItem;

import java.util.Date;

/**
 * This class is used to verify whether the revocation data check shall be skipped for the given certificate
 *
 * @param <T> {@link XmlConstraintsConclusion}
 *
 */
public class RevocationDataRequiredCheck<T extends XmlConstraintsConclusion> extends AbstractCertificateCheckItem<T> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** The validation time */
    private final Date currentTime;

    /** The certificate's sunset date constraint */
    private final LevelConstraint certificateSunsetDateConstraint;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public RevocationDataRequiredCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate,
                                       Date currentTime, LevelConstraint certificateSunsetDateConstraint, CertificateValuesConstraint constraint) {
        super(i18nProvider, result, certificate, constraint);
        this.certificate = certificate;
        this.currentTime = currentTime;
        this.certificateSunsetDateConstraint = certificateSunsetDateConstraint;
    }

    @Override
    public boolean process() {
        return !isTrustAnchor(certificate) && !certificate.isSelfSigned() && !processCertificateCheck(certificate);
    }

    private boolean isTrustAnchor(CertificateWrapper certificate) {
        return ValidationProcessUtils.isTrustAnchor(certificate, currentTime, certificateSunsetDateConstraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_IRDCSFC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_IRDCSFC_ANS;
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
