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

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessDefinition;
import eu.europa.esig.dss.validation.process.vpftsp.checks.TimestampBasicBuildingBlocksCheck;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps extends Chain<XmlValidationProcessTimestamps> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationProcessForTimeStamps.class);

	private final TimestampWrapper timestamp;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	public ValidationProcessForTimeStamps(TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(new XmlValidationProcessTimestamps());
		result.setTitle(ValidationProcessDefinition.VPFTSP.getTitle());

		this.timestamp = timestamp;
		this.bbbs = bbbs;
	}

	@Override
	protected void initChain() {
		XmlBasicBuildingBlocks tspBBB = bbbs.get(timestamp.getId());
		if (tspBBB != null) {
			firstItem = timestampBasicBuildingBlocksValid(tspBBB);
		} else {
			LOG.error("Basic Building Blocks for timestamp '{}' not found!", timestamp.getId());
		}
	}

	@Override
	protected void addAdditionalInfo() {
		result.setId(timestamp.getId());
		result.setType(timestamp.getType().name());
		result.setProductionTime(timestamp.getProductionTime());
	}

	private ChainItem<XmlValidationProcessTimestamps> timestampBasicBuildingBlocksValid(XmlBasicBuildingBlocks timestampBBB) {
		return new TimestampBasicBuildingBlocksCheck(result, timestampBBB, getFailLevelConstraint());
	}

}
