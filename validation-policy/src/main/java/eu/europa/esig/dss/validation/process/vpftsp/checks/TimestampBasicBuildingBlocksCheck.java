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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class TimestampBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessTimestamp> {

	private final XmlBasicBuildingBlocks timestampBBB;

	private Indication indication;
	private SubIndication subIndication;

	public TimestampBasicBuildingBlocksCheck(I18nProvider i18nProvider, XmlValidationProcessTimestamp result, XmlBasicBuildingBlocks timestampBBB,
			LevelConstraint constraint) {
		super(i18nProvider, result, constraint, timestampBBB.getId());

		this.timestampBBB = timestampBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = timestampBBB.getISC();
		if (isc != null) {
			XmlConclusion iscConclusion = isc.getConclusion();
			if (!Indication.PASSED.equals(iscConclusion.getIndication())) {
				indication = iscConclusion.getIndication();
				subIndication = iscConclusion.getSubIndication();
				return false;
			}
		}

		// VCI is skipped

		XmlCV cv = timestampBBB.getCV();
		if (cv != null) {
			XmlConclusion cvConclusion = cv.getConclusion();
			if (!Indication.PASSED.equals(cvConclusion.getIndication())) {
				indication = cvConclusion.getIndication();
				subIndication = cvConclusion.getSubIndication();
				return false;
			}
		}

		XmlXCV xcv = timestampBBB.getXCV();
		if (xcv != null) {
			XmlConclusion xcvConclusion = xcv.getConclusion();
			if (!Indication.PASSED.equals(xcvConclusion.getIndication())) {
				indication = xcvConclusion.getIndication();
				subIndication = xcvConclusion.getSubIndication();
				return false;
			}
		}

		XmlSAV sav = timestampBBB.getSAV();
		if (sav != null) {
			XmlConclusion savConclusion = sav.getConclusion();
			if (!Indication.PASSED.equals(savConclusion.getIndication())) {
				indication = savConclusion.getIndication();
				subIndication = savConclusion.getSubIndication();
				return false;
			}
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
