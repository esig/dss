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
package eu.europa.esig.dss.validation.process.vpfltvd;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationBasicValidation;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.xcv.crs.CertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.AcceptableRevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.RevocationDataAcceptableCheck;

import java.util.Date;
import java.util.Map;

/**
 * Verifies and returns the latest acceptable revocation data for a long-term validation process
 *
 */
public class LongTermValidationCertificateRevocationSelector extends CertificateRevocationSelector {

    /** Diagnostic Data */
    private final DiagnosticData diagnosticData;

    /** Map of BasicBuildingBlocks */
    protected final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Id of a token being validated (e.g. signature id, timestamp id) */
    protected final String tokenId;

    /**
     * Default constructor
     *
     * @param i18nProvider     {@link I18nProvider}
     * @param certificate      {@link CertificateWrapper}
     * @param currentTime      {@link Date} validation time
     * @param diagnosticData   {@link DiagnosticData}
     * @param bbbs             a map of {@link XmlBasicBuildingBlocks}
     * @param tokenId          {@link String} id of a token being validated
     * @param validationPolicy {@link ValidationPolicy}
     */
    public LongTermValidationCertificateRevocationSelector(I18nProvider i18nProvider, CertificateWrapper certificate,
                                                           Date currentTime, DiagnosticData diagnosticData,
                                                           Map<String, XmlBasicBuildingBlocks> bbbs, String tokenId,
                                                           ValidationPolicy validationPolicy) {
        super(i18nProvider, certificate, currentTime, validationPolicy);
        this.diagnosticData = diagnosticData;
        this.bbbs = bbbs;
        this.tokenId = tokenId;
    }

    /**
     * Default constructor
     *
     * @param i18nProvider     {@link I18nProvider}
     * @param certificate      {@link CertificateWrapper}
     * @param currentTime      {@link Date} validation time
     * @param bbbs             a map of {@link XmlBasicBuildingBlocks}
     * @param tokenId          {@link String} id of a token being validated
     * @param validationPolicy {@link ValidationPolicy}
     */
    protected LongTermValidationCertificateRevocationSelector(I18nProvider i18nProvider, CertificateWrapper certificate,
                                                           Date currentTime, Map<String, XmlBasicBuildingBlocks> bbbs,
                                                           String tokenId, ValidationPolicy validationPolicy) {
        this(i18nProvider, certificate, currentTime, null, bbbs, tokenId, validationPolicy);
    }

    @Override
    protected ChainItem<XmlCRS> verifyRevocationData(ChainItem<XmlCRS> item, CertificateRevocationWrapper revocationWrapper) {
        XmlConclusion revocationBBBConclusion = getRevocationBBBConclusion(revocationWrapper);

        if (revocationBBBConclusion != null) {
            if (item == null) {
                item = firstItem = revocationBasicValidationAcceptable(revocationWrapper.getId(), revocationBBBConclusion);
            } else {
                item = item.setNextItem(revocationBasicValidationAcceptable(revocationWrapper.getId(), revocationBBBConclusion));
            }
            if (ValidationProcessUtils.isAllowedBasicRevocationDataValidation(revocationBBBConclusion)) {
                item = super.verifyRevocationData(item, revocationWrapper);
            }
        }

        boolean allowedBBB = ValidationProcessUtils.isAllowedBasicRevocationDataValidation(revocationBBBConclusion);

        Boolean validity = revocationDataValidityMap.get(revocationWrapper);
        if (validity == null) {
            validity = allowedBBB;
        } else {
            validity = validity && allowedBBB;
        }
        revocationDataValidityMap.put(revocationWrapper, validity);

        return item;
    }

    /**
     * Returns a conclusion of the revocation basic building block execution process
     *
     * @param revocationWrapper {@link CertificateRevocationWrapper}
     * @return {@link XmlConclusion}
     */
    protected XmlConclusion getRevocationBBBConclusion(CertificateRevocationWrapper revocationWrapper) {
        RevocationBasicValidationProcess rbvp = new RevocationBasicValidationProcess(
                i18nProvider, diagnosticData, revocationWrapper, bbbs);
        XmlRevocationBasicValidation revocationBasicValidationResult = rbvp.execute();
        return revocationBasicValidationResult.getConclusion();
    }

    @Override
    protected XmlRAC getRevocationAcceptanceValidationResult(CertificateRevocationWrapper revocationWrapper) {
        return getRevocationAcceptanceValidationResult(revocationWrapper.getId());
    }

    private XmlRAC getRevocationAcceptanceValidationResult(String revocationId) {
        XmlBasicBuildingBlocks tokenBBB = bbbs.get(tokenId);
        return ValidationProcessUtils.getRevocationAcceptanceCheckerResult(tokenBBB, certificate.getId(), revocationId);
    }

    private ChainItem<XmlCRS> revocationBasicValidationAcceptable(String revocationId, XmlConclusion revocationBBBConclusion) {
        return new RevocationDataAcceptableCheck<>(i18nProvider, result, revocationId, revocationBBBConclusion, getWarnLevelConstraint());
    }

    @Override
    protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
        if (XmlBlockType.REV_BBB.equals(constraint.getBlockType()) && !isValid(result)) {
            collectMessagesForBBB(conclusion, constraint);
        }
        if (XmlBlockType.RAC.equals(constraint.getBlockType()) && !isValid(result)) {
            XmlRAC xmlRAC = getRevocationAcceptanceValidationResult(constraint.getId());
            if (xmlRAC != null) {
                collectAllMessages(conclusion, xmlRAC.getConclusion());
            }
        }
        super.collectMessages(conclusion, constraint);
    }

    private void collectMessagesForBBB(XmlConclusion conclusion, XmlConstraint constraint) {
        super.collectMessages(conclusion, constraint);
        XmlBasicBuildingBlocks xmlBasicBuildingBlocks = bbbs.get(constraint.getId());
        collectAllMessages(conclusion, xmlBasicBuildingBlocks.getConclusion());
    }

    @Override
    protected ChainItem<XmlCRS> acceptableRevocationDataAvailable() {
        return new AcceptableRevocationDataAvailableCheck<XmlCRS>(i18nProvider, result, getLatestAcceptableCertificateRevocation(), getFailLevelConstraint()) {

            @Override
            protected Indication getFailedIndicationForConclusion() {
                return Indication.INDETERMINATE;
            }

            @Override
            protected SubIndication getFailedSubIndicationForConclusion() {
                return SubIndication.TRY_LATER;
            }

        };
    }

}
