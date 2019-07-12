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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationBasicBuildingBlocksCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final XmlBasicBuildingBlocks revocationBBB;

	private Indication indication;
	private SubIndication subIndication;
	private List<XmlName> errors;

	public RevocationBasicBuildingBlocksCheck(XmlValidationProcessLongTermData result, XmlBasicBuildingBlocks revocationBBB, LevelConstraint constraint) {
		super(result, constraint, revocationBBB.getId());

		this.revocationBBB = revocationBBB;
	}

	@Override
	protected boolean process() {

		// Format check is skipped

		XmlISC isc = revocationBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!isAllowed(iscConclusion)) {
			indication = iscConclusion.getIndication();
			subIndication = iscConclusion.getSubIndication();
			errors = iscConclusion.getErrors();
			return false;
		}

		// VCI is skipped

		XmlCV cv = revocationBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!isAllowed(cvConclusion)) {
			indication = cvConclusion.getIndication();
			subIndication = cvConclusion.getSubIndication();
			errors = cvConclusion.getErrors();
			return false;
		}

		XmlXCV xcv = revocationBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!isAllowed(xcvConclusion)) {
			indication = xcvConclusion.getIndication();
			subIndication = xcvConclusion.getSubIndication();
			errors = xcvConclusion.getErrors();
			return false;
		}

		XmlSAV sav = revocationBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (!isAllowed(savConclusion)) {
			indication = savConclusion.getIndication();
			subIndication = savConclusion.getSubIndication();
			errors = savConclusion.getErrors();
			return false;
		}

		return true;
	}

	private boolean isAllowed(XmlConclusion conclusion) {
		boolean allowed = Indication.PASSED.equals(conclusion.getIndication()) || (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.REVOKED_NO_POE.equals(conclusion.getSubIndication())
						|| SubIndication.OUT_OF_BOUNDS_NO_POE.equals(conclusion.getSubIndication())));
		return allowed;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_RORPIIC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_RORPIIC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return errors;
	}

}
