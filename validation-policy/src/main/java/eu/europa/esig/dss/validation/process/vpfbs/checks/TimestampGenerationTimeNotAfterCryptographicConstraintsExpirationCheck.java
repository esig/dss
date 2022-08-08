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
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicAlgorithm;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Checks if the generation time of a content timestamp is not after the expiration time
 * of cryptographic constraints concerned by the failure
 *
 */
public class TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck<T extends XmlConstraintsConclusion>
        extends ChainItem<T> {

    /** The content timestamp */
    private final TimestampWrapper contentTimestamp;

    /** Cryptographic validation result summary */
    private final XmlCryptographicValidation cryptographicValidation;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param contentTimestamp {@link TimestampWrapper}
     * @param cryptographicValidation {@link XmlCryptographicValidation} cryptographic constraints validation result
     * @param constraint {@link LevelConstraint}
     */
    public TimestampGenerationTimeNotAfterCryptographicConstraintsExpirationCheck(I18nProvider i18nProvider, T result,
                           TimestampWrapper contentTimestamp, XmlCryptographicValidation cryptographicValidation, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, contentTimestamp.getId());
        this.contentTimestamp = contentTimestamp;
        this.cryptographicValidation = cryptographicValidation;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.CNT_TST_BBB;
    }

    @Override
    protected boolean process() {
        return contentTimestamp.getProductionTime() != null && cryptographicValidation.getNotAfter() != null &&
                !contentTimestamp.getProductionTime().after(cryptographicValidation.getNotAfter());
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CRYPTO_CONSTRAINTS_FAILURE;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_ICTGTNACCET;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_ICTGTNACCET_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        String tstGenerationTime = contentTimestamp.getProductionTime() == null ? " ? " : ValidationProcessUtils.getFormattedDate(contentTimestamp.getProductionTime());
        String cryptoConstraintsExpiration = cryptographicValidation.getNotAfter() == null ? " ? " : ValidationProcessUtils.getFormattedDate(cryptographicValidation.getNotAfter());

        String algorithmName = "?";
        XmlCryptographicAlgorithm algorithm = cryptographicValidation.getAlgorithm();
        if (algorithm != null) {
            algorithmName = algorithm.getName();
            if (algorithm.getKeyLength() != null) {
                algorithmName += " with keyLength '" + algorithm.getKeyLength() + "'";
            }
        }

        return i18nProvider.getMessage(MessageTag.TIMESTAMP_AND_CRYPTO_CONSTRAINTS_EXPIRATION, contentTimestamp.getId(),
                tstGenerationTime, algorithmName, cryptoConstraintsExpiration);
    }

}
