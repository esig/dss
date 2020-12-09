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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpftsp.checks.TimestampBasicBuildingBlocksCheck;

import java.util.Map;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamp extends Chain<XmlValidationProcessTimestamp> {

	/** Diagnostic data */
	private final DiagnosticData diagnosticData;

	/** Timestamp to validate */
	private final TimestampWrapper timestamp;

	/** Map of BasicBuildingBlocks */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param timestamp {@link TimestampWrapper}
	 * @param bbbs map of BasicBuildingBlocks
	 */
	public ValidationProcessForTimeStamp(I18nProvider i18nProvider, DiagnosticData diagnosticData,
										 TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(i18nProvider, new XmlValidationProcessTimestamp());

		this.diagnosticData = diagnosticData;
		this.timestamp = timestamp;
		this.bbbs = bbbs;
	}

	@Override
	protected MessageTag getTitle() {
		return MessageTag.VPFTSP;
	}

	@Override
	protected void initChain() {
		firstItem = timestampBasicBuildingBlocksValid();
	}

	@Override
	protected void addAdditionalInfo() {
		result.setType(timestamp.getType().name());
		result.setProductionTime(timestamp.getProductionTime());
	}

	private ChainItem<XmlValidationProcessTimestamp> timestampBasicBuildingBlocksValid() {
		XmlBasicBuildingBlocks timestampBBB = bbbs.get(timestamp.getId());
		if (timestampBBB == null) {
			throw new IllegalStateException(String.format("Missing Basic Building Blocks result for token '%s'", timestamp.getId()));
		}
		return new TimestampBasicBuildingBlocksCheck(i18nProvider, result, diagnosticData, timestampBBB, bbbs, getFailLevelConstraint());
	}

}
