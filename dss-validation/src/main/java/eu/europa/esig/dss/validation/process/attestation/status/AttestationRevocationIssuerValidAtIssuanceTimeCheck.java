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
package eu.europa.esig.dss.validation.process.attestation.status;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks whether the issuer certificate of the attestation revocation token was valid at the attestation revocation token issuance time
 *
 */
public class AttestationRevocationIssuerValidAtIssuanceTimeCheck extends ChainItem<XmlSAV> {

    /** attestation revocation token to check */
    private final AttestationRevocationTokenWrapper attestationRevocationToken;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param attestationRevocationToken {@link AttestationRevocationWrapper}
     * @param constraint {@link LevelRule}
     */
    public AttestationRevocationIssuerValidAtIssuanceTimeCheck(I18nProvider i18nProvider, XmlSAV result,
                                                               AttestationRevocationTokenWrapper attestationRevocationToken, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.attestationRevocationToken = attestationRevocationToken;
    }

    @Override
    protected boolean process() {
        Date issuedAt = attestationRevocationToken.getIssuedAt();
        CertificateWrapper signingCertificate = attestationRevocationToken.getSigningCertificate();
        return issuedAt != null && signingCertificate != null
                && !issuedAt.before(signingCertificate.getNotBefore())
                && !issuedAt.after(signingCertificate.getNotAfter());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.EAA_REV_ISS_VALID;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.EAA_REV_ISS_VALID_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (attestationRevocationToken.getSigningCertificate() != null) {
            return i18nProvider.getMessage(MessageTag.EAA_REV_ISS_CERT, ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getIssuedAt()),
                    ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getSigningCertificate().getNotBefore()),
                    ValidationProcessUtils.getFormattedDate(attestationRevocationToken.getSigningCertificate().getNotAfter()));
        }
        return null;
    }


    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.ATTESTATION_CONSTRAINTS_FAILURE;
    }

}
