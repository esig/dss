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

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class TimestampBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessTimestamps> {

	private final XmlBasicBuildingBlocks timestampBBB;

	private Indication indication;
	private SubIndication subIndication;

	public TimestampBasicBuildingBlocksCheck(XmlValidationProcessTimestamps result, XmlBasicBuildingBlocks timestampBBB, LevelConstraint constraint) {
		super(result, constraint, timestampBBB.getId());

		this.timestampBBB = timestampBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = timestampBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!Indication.PASSED.equals(iscConclusion.getIndication())) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			return false;
		}

		// VCI is skipped

		XmlCV cv = timestampBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.PASSED.equals(cvConclusion.getIndication())) {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			return false;
		}

		XmlXCV xcv = timestampBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!Indication.PASSED.equals(xcvConclusion.getIndication())) {
			indication = xcvConclusion.getIndication();
			subIndication = xcvConclusion.getSubIndication();
			return false;
		}

		XmlSAV sav = timestampBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (!Indication.PASSED.equals(savConclusion.getIndication())) {
			indication = savConclusion.getIndication();
			subIndication = savConclusion.getSubIndication();
			return false;
		}

		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_ROTVPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_ROTVPIIC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

}
