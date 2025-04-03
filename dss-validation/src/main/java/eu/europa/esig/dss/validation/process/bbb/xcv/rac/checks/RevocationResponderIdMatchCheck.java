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
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
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
     * @param constraint {@link LevelRule}
     */
    public RevocationResponderIdMatchCheck(I18nProvider i18nProvider, XmlRAC result, RevocationWrapper revocationData,
                                           LevelRule constraint) {
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
