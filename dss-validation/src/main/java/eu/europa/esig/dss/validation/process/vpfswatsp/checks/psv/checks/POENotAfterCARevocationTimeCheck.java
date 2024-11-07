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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.Collection;
import java.util.Date;

/**
 * This class verifies if there is a POE for the revocation information of the signer certificate
 * at (or before) the revocation time of the CA certificate
 *
 * @param <R> implementation of the revocation data wrapper (CRL/OCSP)
 */
public class POENotAfterCARevocationTimeCheck<R extends RevocationWrapper> extends ChainItem<XmlPSV> {

    /** A collection of filtered acceptable revocation data */
    private final Collection<R> revocationData;

    /** The revocation time of the CA certificate */
    private final Date caRevocationTime;

    /** A collection of POEs */
    private final POEExtraction poeExtraction;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlPSV}
     * @param revocationData a collection of acceptable revocation data for the signing certificate
     * @param caRevocationTime {@link Date} revocation time of CA certificate
     * @param poeExtraction {@link POEExtraction}
     * @param constraint {@link LevelConstraint}
     */
    public POENotAfterCARevocationTimeCheck(I18nProvider i18nProvider, XmlPSV result,
                                            Collection<R> revocationData, Date caRevocationTime,
                                            POEExtraction poeExtraction, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.revocationData = revocationData;
        this.caRevocationTime = caRevocationTime;
        this.poeExtraction = poeExtraction;
    }

    @Override
    protected boolean process() {
        for (RevocationWrapper revocationWrapper : revocationData) {
            if (poeExtraction.isPOEExists(revocationWrapper.getId(), caRevocationTime)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_ITPRISCNARTCAC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_ITPRISCNARTCAC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.REVOKED_CA_NO_POE;
    }

}
