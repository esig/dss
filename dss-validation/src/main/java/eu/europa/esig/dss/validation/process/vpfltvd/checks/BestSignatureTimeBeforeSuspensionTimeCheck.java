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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks if best-signature-time is before the suspension date (onHold)
 */
public class BestSignatureTimeBeforeSuspensionTimeCheck extends ChainItem<XmlValidationProcessLongTermData> {

    /** Certificate's revocation */
    private final CertificateRevocationWrapper certificateRevocation;

    /** Best signature time */
    private final Date bestSignatureTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessLongTermData}
     * @param certificateRevocation {@link CertificateRevocationWrapper}
     * @param bestSignatureTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public BestSignatureTimeBeforeSuspensionTimeCheck(I18nProvider i18nProvider, XmlValidationProcessLongTermData result,
                                                      CertificateRevocationWrapper certificateRevocation,
                                                      Date bestSignatureTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);

        this.certificateRevocation = certificateRevocation;
        this.bestSignatureTime = bestSignatureTime;
    }

    @Override
    protected boolean process() {
        Date revocationDate = certificateRevocation.getRevocationDate();
        return revocationDate != null && bestSignatureTime.before(revocationDate);
    }

    @Override
    protected String buildAdditionalInfo() {
        String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : ValidationProcessUtils.getFormattedDate(bestSignatureTime);
        String revocationTime = certificateRevocation.getRevocationDate() == null ? " ? " : ValidationProcessUtils.getFormattedDate(certificateRevocation.getRevocationDate());
        return i18nProvider.getMessage(MessageTag.BEST_SIGNATURE_TIME_CERT_SUSPENSION, bestSignatureTimeStr, revocationTime);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_ISTPTBST;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_ISTPTBST_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.TRY_LATER;
    }

}
