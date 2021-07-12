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
package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies if the generation time of a content timestamp is not after the certificate's expiration time
 */
public class TimestampGenerationTimeNotAfterCertificateExpirationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The content timestamp */
    private final TimestampWrapper contentTimestamp;

    /** Signing certificate's notAfter time */
    private final Date signingCertificateNotAfter;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param contentTimestamp {@link TimestampWrapper}
     * @param signingCertificateNotAfter {@link Date} notAfter time of a signing certificate
     * @param constraint {@link LevelConstraint}
     */
    public TimestampGenerationTimeNotAfterCertificateExpirationCheck(I18nProvider i18nProvider, T result,
                       TimestampWrapper contentTimestamp, Date signingCertificateNotAfter, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, contentTimestamp.getId());
        this.contentTimestamp = contentTimestamp;
        this.signingCertificateNotAfter = signingCertificateNotAfter;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.CNT_TST_BBB;
    }

    @Override
    protected boolean process() {
        return contentTimestamp.getProductionTime() != null &&
                !contentTimestamp.getProductionTime().after(signingCertificateNotAfter);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.EXPIRED;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_ICTGTNASCET;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_ICTGTNASCET_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        String tstGenerationTime = contentTimestamp.getProductionTime() == null ? " ? " : ValidationProcessUtils.getFormattedDate(contentTimestamp.getProductionTime());
        String certificateNotAfter = signingCertificateNotAfter == null ? " ? " : ValidationProcessUtils.getFormattedDate(signingCertificateNotAfter);
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_AND_REVOCATION_TIME, contentTimestamp.getId(), tstGenerationTime, certificateNotAfter);
    }

}
