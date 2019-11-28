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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class PastTimestampValidation extends ChainItem<XmlValidationProcessArchivalData> {
	
	private XmlPSV xmlPSV;
	private XmlSAV xmlSAV;

	private Indication indication;
	private SubIndication subIndication;
	
	private static final String PSV_BLOCK_SUFFIX = "-PSV";

	public PastTimestampValidation(XmlValidationProcessArchivalData result, XmlPSV xmlPSV, XmlSAV xmlSAV, 
			TimestampWrapper timestamp, LevelConstraint constraint) {
		super(result, constraint, timestamp.getId() + PSV_BLOCK_SUFFIX);
		this.xmlPSV = xmlPSV;
		this.xmlSAV = xmlSAV;
	}

	@Override
	protected boolean process() {
		if (!isValid(xmlPSV)) {
			indication = xmlPSV.getConclusion().getIndication();
			subIndication = xmlPSV.getConclusion().getSubIndication();
			return false;
		} else if (!isValid(xmlSAV)) {
			indication = xmlSAV.getConclusion().getIndication();
			subIndication = xmlSAV.getConclusion().getSubIndication();
			return false;
		}
		return true;
	}

	@Override
	protected String getMessageTag() {
		return "PSV_IPTVC";
	}

	@Override
	protected String getErrorMessageTag() {
		return "PSV_IPTVC_ANS";
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
