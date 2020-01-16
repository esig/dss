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
package eu.europa.esig.dss.validation.process.vpftsp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpftsp.checks.TimestampBasicBuildingBlocksCheck;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamp extends Chain<XmlValidationProcessTimestamp> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationProcessForTimeStamp.class);

	private final TimestampWrapper timestamp;
	private final XmlBasicBuildingBlocks timestampBBB;

	public ValidationProcessForTimeStamp(I18nProvider i18nProvider, TimestampWrapper timestamp, XmlBasicBuildingBlocks timestampBBB) {
		super(i18nProvider, new XmlValidationProcessTimestamp());
		this.timestamp = timestamp;
		this.timestampBBB = timestampBBB;
	}
	
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VPFTSP;
	}

	@Override
	protected void initChain() {
		if (timestampBBB != null) {
			firstItem = timestampBasicBuildingBlocksValid(timestampBBB);
		} else {
			LOG.error("Basic Building Blocks for timestamp '{}' not found!", timestamp.getId());
		}
	}

	@Override
	protected void addAdditionalInfo() {
		result.setType(timestamp.getType().name());
		result.setProductionTime(timestamp.getProductionTime());
	}

	private ChainItem<XmlValidationProcessTimestamp> timestampBasicBuildingBlocksValid(XmlBasicBuildingBlocks timestampBBB) {
		return new TimestampBasicBuildingBlocksCheck(i18nProvider, result, timestampBBB, getFailLevelConstraint());
	}

}
