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
package eu.europa.esig.dss.validation.process.vpftsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether the validation result of EN 319 102-1 ch. "5.4 Time-stamp validation building block" process is valid
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class BasicTimestampValidationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The timestamp to check */
    protected final TimestampWrapper timestamp;

    /** Timestamp validation result */
    private final XmlValidationProcessBasicTimestamp timestampValidationResult;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link T}
     * @param timestamp {@link TimestampWrapper}
     * @param timestampValidationResult {@link XmlValidationProcessBasicTimestamp}
     * @param constraint {@link LevelConstraint}
     */
    public BasicTimestampValidationCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                         XmlValidationProcessBasicTimestamp timestampValidationResult,
                                         LevelConstraint constraint) {
        this(i18nProvider, result, timestamp, timestampValidationResult, constraint, null);
    }

    /**
     * Constructor to instantiate check with Id provided
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param timestamp {@link TimestampWrapper}
     * @param constraint {@link LevelConstraint}
     */
    protected BasicTimestampValidationCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                           XmlValidationProcessBasicTimestamp timestampValidationResult,
                                           LevelConstraint constraint, String bbbId) {
        super(i18nProvider, result, constraint, bbbId);
        this.timestamp = timestamp;
        this.timestampValidationResult = timestampValidationResult;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.TST_BBB;
    }

    @Override
    protected boolean process() {
        return isValid(timestampValidationResult);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_IBSVPTC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_IBSVPTC_ANS;
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
