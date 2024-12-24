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
package eu.europa.esig.dss.validation.process.vpftsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.vpfbs.AbstractBasicValidationProcess;

import java.util.Map;

/**
 * Performs Time-stamp validation building block as per clause 5.4
 *
 */
public class TimestampBasicValidationProcess extends AbstractBasicValidationProcess<XmlValidationProcessBasicTimestamp> {

    /**
     * Timestamp being validated
     */
    private final TimestampWrapper timestamp;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param timestamp {@link TimestampWrapper}
     * @param bbbs           map of BasicBuildingBlocks
     */
    public TimestampBasicValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                                           TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, new XmlValidationProcessBasicTimestamp(), diagnosticData, timestamp, bbbs);
        this.timestamp = timestamp;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPFTSP;
    }

    @Override
    protected void addAdditionalInfo() {
        result.setType(timestamp.getType().name());
        result.setProductionTime(timestamp.getProductionTime());
    }

}
