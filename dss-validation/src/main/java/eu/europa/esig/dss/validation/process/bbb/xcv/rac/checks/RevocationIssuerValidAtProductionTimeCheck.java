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
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
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
     * @param constraint {@link LevelRule}
     */
    public RevocationIssuerValidAtProductionTimeCheck(I18nProvider i18nProvider, XmlRAC result,
                                                      RevocationWrapper revocationData, LevelRule constraint) {
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
