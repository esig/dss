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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Checks whether the validation of timestamp with a Past Signature Validation process succeed.
 * See EN 319 102-1 ch. "5.6.3 Validation Process for Signatures providing Long Term Availability and Integrity of Validation Material"
 * step 5) of the "5.6.3.4 Processing".
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class TimestampValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The timestamp to check */
    private final TimestampWrapper timestamp;

    /** Timestamp validation result */
    private final XmlValidationProcessArchivalDataTimestamp timestampValidationResult;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link T}
     * @param timestamp {@link TimestampWrapper}
     * @param timestampValidationResult {@link XmlValidationProcessArchivalDataTimestamp}
     * @param constraint {@link LevelRule}
     */
    public TimestampValidationCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                    XmlValidationProcessArchivalDataTimestamp timestampValidationResult,
                                    LevelRule constraint) {
        super(i18nProvider, result, constraint, timestamp.getId());
        this.timestamp = timestamp;
        this.timestampValidationResult = timestampValidationResult;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.TST;
    }

    @Override
    protected boolean process() {
        return isValid(timestampValidationResult);
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                ValidationProcessUtils.getTimestampTypeMessageTag(timestamp.getType()), timestamp.getId(), date);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_IBSVPTADC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_IBSVPTADC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return timestampValidationResult.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return timestampValidationResult.getConclusion().getSubIndication();
    }

}
