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
package eu.europa.esig.dss.validation.process.bbb.xcv.crs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.RevocationAcceptanceChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationAcceptanceCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.AcceptableRevocationDataAvailableCheck;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class validates revocation data for a given certificate and returns the latest valid entry
 *
 */
public class CertificateRevocationSelector extends Chain<XmlCRS> {

    /** Certificate to get a latest valid revocation data for */
    protected final CertificateWrapper certificate;

    /** Validation time */
    protected final Date currentTime;

    /** Validation policy */
    protected final ValidationPolicy validationPolicy;

    /** This map contains validation results of the revocation data processing */
    protected final Map<RevocationWrapper, Boolean> revocationDataValidityMap = new HashMap<>();

    /** Internal set of processed tokens (avoids infinite loop) */
    private final Set<String> validatedTokens;

    /** The latest acceptable certificate revocation, to be returned after the selector execution */
    private CertificateRevocationWrapper latestCertificateRevocation;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param certificate {@link CertificateWrapper}
     * @param currentTime {@link Date} validation time
     * @param validationPolicy {@link ValidationPolicy}
     */
    public CertificateRevocationSelector(I18nProvider i18nProvider, CertificateWrapper certificate, Date currentTime,
                                         ValidationPolicy validationPolicy) {
        this(i18nProvider, certificate, currentTime, validationPolicy, new HashSet<>());
    }

    /**
     * Constructor with a set of validated tokens
     *
     * @param i18nProvider {@link I18nProvider}
     * @param certificate {@link CertificateWrapper}
     * @param currentTime {@link Date} validation time
     * @param validationPolicy {@link ValidationPolicy}
     * @param validatedTokens a set of token {@link String} identifiers that have been already processed
     */
    public CertificateRevocationSelector(I18nProvider i18nProvider, CertificateWrapper certificate, Date currentTime,
                                         ValidationPolicy validationPolicy, Set<String> validatedTokens) {
        super(i18nProvider, new XmlCRS());
        this.certificate = certificate;
        this.currentTime = currentTime;
        this.validationPolicy = validationPolicy;
        this.validatedTokens = validatedTokens;

        result.setId(certificate.getId());
        this.validatedTokens.add(certificate.getId());
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.CRS;
    }

    @Override
    protected void initChain() {
        ChainItem<XmlCRS> item = null;

        for (CertificateRevocationWrapper revocationWrapper : getCertificateRevocationData()) {

            item = verifyRevocationData(item, revocationWrapper);

            if (Boolean.TRUE.equals(revocationDataValidityMap.get(revocationWrapper)) &&
                    (latestCertificateRevocation == null || (revocationWrapper.getProductionDate() != null &&
                                    latestCertificateRevocation.getProductionDate().before(revocationWrapper.getProductionDate())) )) {
                latestCertificateRevocation = revocationWrapper;
            }
        }

        if (latestCertificateRevocation != null) {
            result.setLatestAcceptableRevocationId(latestCertificateRevocation.getId());
        }

        if (item == null) {
            item = firstItem = acceptableRevocationDataAvailable();
        } else {
            item = item.setNextItem(acceptableRevocationDataAvailable());
        }
    }

    /**
     * Returns available certificate revocation data to be validated
     *
     * @return a list of {@link CertificateRevocationWrapper}s
     */
    protected List<CertificateRevocationWrapper> getCertificateRevocationData() {
        return certificate.getCertificateRevocationData();
    }

    /**
     * Verifies the given revocation data and returns the resulting {@code ChainItem}
     *
     * @param item {@link ChainItem} the last initialized chain item to be processed
     *                              in prior to the revocation validation
     * @param revocationWrapper {@link CertificateRevocationWrapper to be verified}
     * @return {@link ChainItem}
     */
    protected ChainItem<XmlCRS> verifyRevocationData(ChainItem<XmlCRS> item, CertificateRevocationWrapper revocationWrapper) {
        XmlRAC racResult = getRevocationAcceptanceValidationResult(revocationWrapper);

        if (racResult != null) {
            if (item == null) {
                item = firstItem = revocationAcceptable(racResult);
            } else {
                item = item.setNextItem(revocationAcceptable(racResult));
            }
        }

        revocationDataValidityMap.put(revocationWrapper, isValid(racResult));

        return item;
    }

    /**
     * Returns a RevocationAcceptanceValidation result for the given revocation token
     *
     * @param revocationWrapper {@link CertificateRevocationWrapper}
     * @return {@link XmlRAC}
     */
    protected XmlRAC getRevocationAcceptanceValidationResult(CertificateRevocationWrapper revocationWrapper) {
        RevocationAcceptanceChecker rac = new RevocationAcceptanceChecker(
                i18nProvider, certificate, revocationWrapper, currentTime, validationPolicy, validatedTokens);
        XmlRAC racResult = rac.execute();

        result.getRAC().add(racResult);

        return racResult;
    }

    /**
     * This method returns the latest acceptable certificate revocation data
     *
     * NOTE: method {@code execute()} shall be called before
     *
     * @return {@link CertificateRevocationWrapper}
     */
    public CertificateRevocationWrapper getLatestAcceptableCertificateRevocation() {
        return latestCertificateRevocation;
    }

    private ChainItem<XmlCRS> revocationAcceptable(XmlRAC racResult) {
        return new RevocationAcceptanceCheckerResultCheck<>(i18nProvider, result, racResult, getWarnLevelConstraint());
    }

    /**
     * Checks whether the acceptable revocation data is available
     *
     * @return {@link ChainItem}
     */
    protected ChainItem<XmlCRS> acceptableRevocationDataAvailable() {
        return new AcceptableRevocationDataAvailableCheck<>(i18nProvider, result, latestCertificateRevocation, getFailLevelConstraint());
    }

    @Override
    protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
        // collect all messages from not RAC checks, collect from RAC only when all of them failed
        if (!XmlBlockType.RAC.equals(constraint.getBlockType()) || !isValid(result)) {
            super.collectMessages(conclusion, constraint);
        }
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        if (!isValid(result)) {
            for (XmlRAC rac : result.getRAC()) {
                super.collectAllMessages(conclusion, rac.getConclusion());
            }
        } else {
            // collect additional messages for the valid RAC(s)
            for (XmlRAC rac : result.getRAC()) {
                if (isValid(rac)) {
                    super.collectAllMessages(conclusion, rac.getConclusion());
                }
            }
        }
    }

}
