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
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AttestationRevocationWrapper;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.eaa.checks.AcceptableAttestationRevocationFoundCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationAdministrativeExpirationDatePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationAdministrativeIssuanceDatePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationAdministrativePeriodNotExpiredCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationCategoryCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationClaimsCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationExpirationPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationIdentifierPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationIssuanceDatePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationIssuingAuthorityCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationIssuingAuthorityRegistrationIdentifierCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationIssuingCountryCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationNotBeforePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationNotExpiredCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationNotOnHoldCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationNotRevokedCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationOneTimeUseCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationPseudonymUsageCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationRevocationAcceptableCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationRevocationAvailableCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationRevocationPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationRevocationStatusKnownCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationShortLivedCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationSubjectCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationSubjectPseudonymCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationSupportedClaimsCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationSupportedNamespacesCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationTypeCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.AttestationTypeIntegrityPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.ETSI194721ConformanceCheck;

import java.util.Date;
import java.util.Map;

/**
 * Performs verification of EAA against the validationPolicy defined acceptance criteria
 *
 */
public class AttestationAcceptanceValidation extends AbstractAcceptanceValidation<AttestationWrapper> {

    /** A map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Last acceptable EAA token status */
    private AttestationRevocationWrapper lastAcceptableStatus;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param currentTime {@link Date} validation time
     * @param attestationWrapper {@link AttestationWrapper}
     * @param bbbs a map of {@link XmlBasicBuildingBlocks}s
     * @param aov {@link XmlAOV}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public AttestationAcceptanceValidation(I18nProvider i18nProvider, Date currentTime,
                                           AttestationWrapper attestationWrapper, Map<String, XmlBasicBuildingBlocks> bbbs, XmlAOV aov,
                                           ValidationPolicy validationPolicy) {
        super(i18nProvider, attestationWrapper, currentTime, Context.EAA, aov, validationPolicy);
        this.bbbs = bbbs;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
    }

    @Override
    protected void initChain() {
        ChainItem<XmlSAV> item = firstItem = etsi194721Conformance();

        item = item.setNextItem(eaaType());
        if (AttestationFormat.SD_JWT_VC == token.getEAAType()) {
            item = item.setNextItem(typeIntegrityPresent());
        }

        if (AttestationFormat.ISO_IEC_MDOC == token.getEAAType()) {
            item = item.setNextItem(issuanceDatePresent());
        }

        item = item.setNextItem(eaaIdentifierPresent());

        item = item.setNextItem(notBeforePresent());

        item = item.setNextItem(expirationPresent());

        if (token.getNotBefore() != null && token.getExpiration() != null) {
            item = item.setNextItem(notExpired());
        }

        item = item.setNextItem(administrativeIssuanceDatePresent());

        item = item.setNextItem(administrativeExpirationDatePresent());

        if (token.getAdministrativeIssuanceDate() != null && token.getAdministrativeExpirationDate() != null) {
            item = item.setNextItem(administrativePeriodNotExpired());
        }

        item = item.setNextItem(category());

        item = item.setNextItem(subject());

        item = item.setNextItem(subjectPseudonym());

        item = item.setNextItem(issuingCountry());

        item = item.setNextItem(issuingAuthority());

        item = item.setNextItem(issuingAuthorityRegistrationIdentifier());

        if (Utils.isTrue(token.getOneTimeUse())) {
            item = item.setNextItem(oneTimeUse());
        }

        if (Utils.isTrue(token.getShortLived())) {

            item = item.setNextItem(shortLived());

        } else {

            // TODO : make status check configurable ?

            AttestationRevocationPresentCheck revocationPresentCheck = statusPresent();

            item = item.setNextItem(revocationPresentCheck);

            if (revocationPresentCheck.process()) {

                item = item.setNextItem(statusAvailable());

                // TODO : improve with EAA Status selector ?
                lastAcceptableStatus = null;
                for (AttestationRevocationWrapper revocationWrapper : token.getAttestationRevocations()) {

                    XmlBasicBuildingBlocks eaaRevocationBBB = bbbs.get(revocationWrapper.getId());
                    if (eaaRevocationBBB == null) {
                        throw new IllegalStateException(String.format("No BasicBuildingBlock found for token with Id '%s'", revocationWrapper.getId()));
                    }

                    item = item.setNextItem(statusKnown(revocationWrapper));

                    item = item.setNextItem(statusAcceptable(revocationWrapper, eaaRevocationBBB.getConclusion()));

                    if (isValidConclusion(eaaRevocationBBB.getConclusion())
                            && (lastAcceptableStatus == null || lastAcceptableStatus.getIssuedAt().before(revocationWrapper.getIssuedAt()))) {
                        lastAcceptableStatus = revocationWrapper;
                    }

                }

                item = item.setNextItem(acceptableStatusFound(lastAcceptableStatus));

                if (lastAcceptableStatus != null) {

                    item = item.setNextItem(notRevoked(lastAcceptableStatus));

                    item = item.setNextItem(notOnHold(lastAcceptableStatus));

                }

            }

        }

        if (token.getPseudonym() != null) {
            item = item.setNextItem(usePseudonym());
        }

        item = item.setNextItem(claims());

        item = item.setNextItem(supportedClaims());

        if (AttestationFormat.ISO_IEC_MDOC == token.getEAAType()) {

            item = item.setNextItem(supportedNamespaces());

        }

        // cryptographic check
        item = cryptographic(item);

    }

    private ChainItem<XmlSAV> etsi194721Conformance() {
        LevelRule constraint = validationPolicy.getEAAETSI194721ConformanceConstraint();
        return new ETSI194721ConformanceCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> eaaType() {
        MultiValuesRule constraint = validationPolicy.getEAATypeConstraint();
        return new AttestationTypeCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> typeIntegrityPresent() {
        LevelRule constraint = validationPolicy.getEAATypeIntegrityPresentConstraint();
        return new AttestationTypeIntegrityPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> notBeforePresent() {
        LevelRule constraint = validationPolicy.getEAANotBeforePresentConstraint();
        return new AttestationNotBeforePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> expirationPresent() {
        LevelRule constraint = validationPolicy.getEAAExpirationPresentConstraint();
        return new AttestationExpirationPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> notExpired() {
        LevelRule constraint = validationPolicy.getEAANotExpiredConstraint();
        return new AttestationNotExpiredCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> administrativeIssuanceDatePresent() {
        LevelRule constraint = validationPolicy.getEAAAdministrativeIssuanceDatePresentConstraint();
        return new AttestationAdministrativeIssuanceDatePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> administrativeExpirationDatePresent() {
        LevelRule constraint = validationPolicy.getEAAAdministrativeExpirationDatePresentConstraint();
        return new AttestationAdministrativeExpirationDatePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> administrativePeriodNotExpired() {
        LevelRule constraint = validationPolicy.getEAAAdministrativePeriodNotExpiredConstraint();
        return new AttestationAdministrativePeriodNotExpiredCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> eaaIdentifierPresent() {
        LevelRule constraint = validationPolicy.getEAAIdentifierPresentConstraint();
        return new AttestationIdentifierPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuanceDatePresent() {
        LevelRule constraint = validationPolicy.getEAAIssuanceDatePresentConstraint();
        return new AttestationIssuanceDatePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> category() {
        MultiValuesRule constraint = validationPolicy.getEAACategoryConstraint();
        return new AttestationCategoryCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> subject() {
        MultiValuesRule constraint = validationPolicy.getEAASubjectConstraint();
        return new AttestationSubjectCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> subjectPseudonym() {
        MultiValuesRule constraint = validationPolicy.getEAASubjectPseudonymConstraint();
        return new AttestationSubjectPseudonymCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuingCountry() {
        MultiValuesRule constraint = validationPolicy.getEAAIssuingCountryConstraint();
        return new AttestationIssuingCountryCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuingAuthority() {
        MultiValuesRule constraint = validationPolicy.getEAAIssuingAuthorityConstraint();
        return new AttestationIssuingAuthorityCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuingAuthorityRegistrationIdentifier() {
        MultiValuesRule constraint = validationPolicy.getEAAIssuingAuthorityRegistrationIdentifierConstraint();
        return new AttestationIssuingAuthorityRegistrationIdentifierCheck(i18nProvider, result, token, constraint);
    }

    private AttestationRevocationPresentCheck statusPresent() {
        LevelRule constraint = validationPolicy.getEAARevocationPresentConstraint();
        return new AttestationRevocationPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> statusAvailable() {
        LevelRule constraint = validationPolicy.getEAARevocationAvailableConstraint();
        return new AttestationRevocationAvailableCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> statusKnown(AttestationRevocationWrapper eaaRevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationUnknownStatusConstraint();
        return new AttestationRevocationStatusKnownCheck(i18nProvider, result, eaaRevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> statusAcceptable(AttestationRevocationWrapper eaaRevocationWrapper, XmlConclusion xmlConclusion) {
        return new AttestationRevocationAcceptableCheck(i18nProvider, result, eaaRevocationWrapper, xmlConclusion, getWarnLevelRule());
    }

    private ChainItem<XmlSAV> acceptableStatusFound(AttestationRevocationWrapper acceptableEAARevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationAvailableConstraint();
        return new AcceptableAttestationRevocationFoundCheck(i18nProvider, result, acceptableEAARevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> notRevoked(AttestationRevocationWrapper eaaRevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationNotRevokedConstraint();
        return new AttestationNotRevokedCheck(i18nProvider, result, eaaRevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> notOnHold(AttestationRevocationWrapper eaaRevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationNotOnHoldConstraint();
        return new AttestationNotOnHoldCheck(i18nProvider, result, eaaRevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> shortLived() {
        LevelRule constraint = validationPolicy.getEAAShortLivedConstraint();
        return new AttestationShortLivedCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> oneTimeUse() {
        LevelRule constraint = validationPolicy.getEAAOneTimeUseConstraint();
        return new AttestationOneTimeUseCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> usePseudonym() {
        LevelRule constraint = validationPolicy.getEAAUsePseudonymConstraint();
        return new AttestationPseudonymUsageCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> claims() {
        MultiValuesRule constraint = validationPolicy.getEAAClaimsConstraint();
        return new AttestationClaimsCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> supportedClaims() {
        MultiValuesRule constraint = validationPolicy.getEAASupportedClaimsConstraint();
        return new AttestationSupportedClaimsCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> supportedNamespaces() {
        MultiValuesRule constraint = validationPolicy.getEAASupportedNamespacesConstraint();
        return new AttestationSupportedNamespacesCheck(i18nProvider, result, token, constraint);
    }

    @Override
    protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
        if (!MessageTag.EAA_REV_ACC.getId().equals(constraint.getName().getKey())) {
            super.collectMessages(conclusion, constraint);
        }
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        super.collectAdditionalMessages(conclusion);

        if (lastAcceptableStatus != null) {
            XmlBasicBuildingBlocks tokenBBB = bbbs.get(lastAcceptableStatus.getId());
            collectAllMessages(conclusion, tokenBBB.getConclusion());
        } else {
            for (AttestationRevocationWrapper EAARevocationWrapper : token.getAttestationRevocations()) {
                XmlBasicBuildingBlocks tokenBBB = bbbs.get(EAARevocationWrapper.getId());
                collectAllMessages(conclusion, tokenBBB.getConclusion());
            }
        }
    }

}
