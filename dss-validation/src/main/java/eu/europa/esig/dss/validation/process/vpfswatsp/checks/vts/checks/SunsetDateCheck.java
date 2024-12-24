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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Checks if the sunset date is defined for the current trust anchor
 *
 */
public class SunsetDateCheck extends ChainItem<XmlVTS> {

    /** Trust anchor to check the sunset date */
    private final CertificateWrapper trustedCertificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlVTS}
     * @param trustedCertificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public SunsetDateCheck(I18nProvider i18nProvider, XmlVTS result, CertificateWrapper trustedCertificate, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, trustedCertificate.getId());
        this.trustedCertificate = trustedCertificate;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.SUB_XCV_TA;
    }

    @Override
    protected boolean process() {
        return trustedCertificate != null && trustedCertificate.getTrustSunsetDate() != null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_ISDDTA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_ISDDTA_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return null;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (trustedCertificate != null && trustedCertificate.getTrustSunsetDate() != null) {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_TRUST_ANCHOR,
                    trustedCertificate.getId(), ValidationProcessUtils.getFormattedDate(trustedCertificate.getTrustSunsetDate()));
        }
        return null;
    }

}
