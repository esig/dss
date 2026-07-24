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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AttestationRevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationExpirationTimeCheck;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationIssuanceTimeCheck;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationIssuerValidAtIssuanceTimeCheck;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationNotExpiredCheck;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationSubjectCheck;
import eu.europa.esig.dss.validation.process.attestation.status.AttestationRevocationSubjectMatchCheck;

import java.util.Date;

/**
 * Performs verification of EAA revocation token against the validationPolicy defined acceptance criteria
 *
 */
public class AttestationRevocationTokenAcceptanceValidation extends AbstractAcceptanceValidation<AttestationRevocationTokenWrapper> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param currentTime {@link Date} validation time
     * @param attestationRevocationTokenWrapper {@link RevocationWrapper}
     * @param aov {@link XmlAOV}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public AttestationRevocationTokenAcceptanceValidation(I18nProvider i18nProvider, Date currentTime,
                                                          AttestationRevocationTokenWrapper attestationRevocationTokenWrapper, XmlAOV aov, ValidationPolicy validationPolicy) {
        super(i18nProvider, attestationRevocationTokenWrapper, currentTime, Context.EAA_REVOCATION, aov, validationPolicy);
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
    }

    @Override
    protected void initChain() {

        ChainItem<XmlSAV> item = firstItem = issuanceTime();

        item = item.setNextItem(expirationTime());

        if (token.getExpirationTime() != null) {
            item = item.setNextItem(notExpired());
        }

        item = item.setNextItem(subject());

        if (token.getSubject() != null) {
            item = item.setNextItem(subjectMatches());
        }

        if (token.getIssuedAt() != null) {
            item = item.setNextItem(issuerValidAtIssuanceTime());
        }

        item = cryptographic(item);

    }

    private ChainItem<XmlSAV> issuanceTime() {
        LevelRule constraint = validationPolicy.getEAARevocationIssuanceTimeConstraint();
        return new AttestationRevocationIssuanceTimeCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> expirationTime() {
        LevelRule constraint = validationPolicy.getEAARevocationExpirationTimeConstraint();
        return new AttestationRevocationExpirationTimeCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> notExpired() {
        LevelRule constraint = validationPolicy.getEAARevocationNotExpiredConstraint();
        return new AttestationRevocationNotExpiredCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> subject() {
        MultiValuesRule constraint = validationPolicy.getAttestationRevocationsubjectConstraint();
        return new AttestationRevocationSubjectCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> subjectMatches() {
        LevelRule constraint = validationPolicy.getAttestationRevocationsubjectMatchConstraint();
        return new AttestationRevocationSubjectMatchCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuerValidAtIssuanceTime() {
        LevelRule constraint = validationPolicy.getEAARevocationIssuerValidAtIssuanceTimeConstraint();
        return new AttestationRevocationIssuerValidAtIssuanceTimeCheck(i18nProvider, result, token, constraint);
    }

}
