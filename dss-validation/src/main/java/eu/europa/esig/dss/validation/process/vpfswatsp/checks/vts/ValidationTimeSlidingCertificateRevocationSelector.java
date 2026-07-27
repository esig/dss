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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.AcceptableRevocationDataAvailableCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.LongTermValidationCertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.POEExistsAtOrBeforeControlTimeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.RevocationIssuedBeforeControlTimeCheck;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Filters revocation data on a "Validation Time Sliding" process
 *
 */
public class ValidationTimeSlidingCertificateRevocationSelector extends LongTermValidationCertificateRevocationSelector {

    /** POE container */
    private final POEExtraction poe;

    /** List of acceptable certificate revocation data for VTS processing */
    private final List<CertificateRevocationWrapper> certificateRevocationData;

    /**
     * Default constructor
     *
     * @param i18nProvider     {@link I18nProvider}
     * @param certificate      {@link CertificateWrapper}
     * @param certificateRevocationData a list of {@link CertificateRevocationWrapper}s
     * @param currentTime      {@link Date} validation time
     * @param bbbs             a map of {@link XmlBasicBuildingBlocks}
     * @param tokenId          {@link String} current token id being validated
     * @param poe              {@link POEExtraction}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public ValidationTimeSlidingCertificateRevocationSelector(
            I18nProvider i18nProvider, CertificateWrapper certificate, List<CertificateRevocationWrapper> certificateRevocationData,
            Date currentTime, Map<String, XmlBasicBuildingBlocks> bbbs, String tokenId, POEExtraction poe, ValidationPolicy validationPolicy) {
        super(i18nProvider, certificate, currentTime, bbbs, tokenId, validationPolicy);
        this.certificateRevocationData = certificateRevocationData;
        this.poe = poe;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VTS_CRS;
    }

    @Override
    public List<CertificateRevocationWrapper> getCertificateRevocationData() {
        return certificateRevocationData;
    }

    @Override
    protected ChainItem<XmlCRS> verifyRevocationData(ChainItem<XmlCRS> item, CertificateRevocationWrapper revocationWrapper) {
        item = super.verifyRevocationData(item, revocationWrapper);

        Boolean validity = revocationDataValidityMap.get(revocationWrapper);
        if (Boolean.TRUE.equals(validity)) {
            item = item.setNextItem(revocationIssuedBeforeControlTime(revocationWrapper, currentTime));

            validity = revocationWrapper.getThisUpdate() != null && revocationWrapper.getThisUpdate().before(currentTime);

            if (Boolean.TRUE.equals(validity)) {

                item = item.setNextItem(poeExistsAtOrBeforeControlTime(certificate, TimestampedObjectType.CERTIFICATE, currentTime));

                item = item.setNextItem(poeExistsAtOrBeforeControlTime(revocationWrapper, TimestampedObjectType.REVOCATION, currentTime));

                validity = poe.isPOEExists(certificate.getId(), currentTime) && poe.isPOEExists(revocationWrapper.getId(), currentTime);

            }

            // update the validity map
            revocationDataValidityMap.put(revocationWrapper, validity);
        }

        return item;
    }

    private ChainItem<XmlCRS> revocationIssuedBeforeControlTime(RevocationWrapper revocation, Date controlTime) {
        return new RevocationIssuedBeforeControlTimeCheck<>(i18nProvider, result, revocation, controlTime, getWarnLevelRule());
    }

    private ChainItem<XmlCRS> poeExistsAtOrBeforeControlTime(TokenProxy token, TimestampedObjectType objectType, Date controlTime) {
        return new POEExistsAtOrBeforeControlTimeCheck<>(i18nProvider, result, token, objectType, controlTime, poe, getWarnLevelRule());
    }

    @Override
    protected ChainItem<XmlCRS> acceptableRevocationDataAvailable() {
        /*
         * If at least one revocation status information is selected, the building block shall go to the next step.
         * If there is no such information, the building block shall return the indication INDETERMINATE with the
         * sub-indication NO_POE.
         */
        return new AcceptableRevocationDataAvailableCheck<XmlCRS>(i18nProvider, result, getLatestAcceptableCertificateRevocation(), getFailLevelRule()) {

            @Override
            protected Indication getFailedIndicationForConclusion() {
                return Indication.INDETERMINATE;
            }

            @Override
            protected SubIndication getFailedSubIndicationForConclusion() {
                return SubIndication.NO_POE;
            }

        };

    }

}
