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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies whether a prospective certificate chain with trust anchors valid
 * at validation time has been found
 *
 */
public class ProspectiveCertificateChainAtValidationTimeCheck extends ChainItem<XmlXCV> {

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
     * @param constraint {@link LevelRule}
     */
    public ProspectiveCertificateChainAtValidationTimeCheck(I18nProvider i18nProvider, XmlXCV result,
                                                      CertificateWrapper certificate, Date controlTime, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.controlTime = controlTime;
    }

    @Override
    protected boolean process() {
        // FAIL level constraint is used to fail the check
        if (ValidationProcessUtils.isTrustAnchor(certificate, controlTime, getFailLevelRule())) {
            return true;
        }
        for (CertificateWrapper caCertificate : certificate.getCertificateChain()) {
            if (ValidationProcessUtils.isTrustAnchor(caCertificate, controlTime, getFailLevelRule())) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_HPCCVVT;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_HPCCVVT_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE;
    }

    private LevelRule getFailLevelRule() {
        return ValidationProcessUtils.getLevelRule(Level.FAIL);
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.VALIDATION_TIME, ValidationProcessUtils.getFormattedDate(controlTime));
    }

}