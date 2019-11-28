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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class CurrentTimeIndicationCheck extends ChainItem<XmlPSV> {

	private final Indication indication;
	private final SubIndication subIndication;
	private final List<XmlName> errors;

	public CurrentTimeIndicationCheck(XmlPSV result, Indication indication, SubIndication subIndication, List<XmlName> errors, LevelConstraint constraint) {
		super(result, constraint);

		this.indication = indication;
		this.subIndication = subIndication;
		this.errors = errors;
	}

	@Override
	protected boolean process() {
		return Indication.PASSED.equals(indication);
	}

	@Override
	protected String getMessageTag() {
		return "PSV_IPCVC";
	}

	@Override
	protected String getErrorMessageTag() {
		return "PSV_IPCVC_ANS";
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
