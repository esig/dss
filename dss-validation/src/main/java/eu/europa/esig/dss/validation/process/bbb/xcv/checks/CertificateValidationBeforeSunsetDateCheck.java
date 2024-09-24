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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
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
 * This class verifies whether a validation time is before certificate's trust sunset date
 *
 */
public class CertificateValidationBeforeSunsetDateCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /** Validation time to check against */
    private final Date controlTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateValidationBeforeSunsetDateCheck(I18nProvider i18nProvider, T result,
                                                      CertificateWrapper certificate, Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, certificate.getId());
        this.certificate = certificate;
        this.controlTime = controlTime;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.SUB_XCV_TA;
    }

    @Override
    protected boolean process() {
        if (certificate.getTrustSunsetDate() != null) {
            return controlTime.before(certificate.getTrustSunsetDate());
        }
        // if no Sunset date, trust indefinitely
        return certificate.isTrusted();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_IVTBCTSD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_IVTBCTSD_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (certificate.getTrustSunsetDate() != null) {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE, ValidationProcessUtils.getFormattedDate(controlTime),
                    ValidationProcessUtils.getFormattedDate(certificate.getTrustSunsetDate()));
        } else {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID);
        }
    }

}