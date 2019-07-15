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

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;

public class PastSignatureValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;
	private final XmlBasicBuildingBlocks bbb;
	private final POEExtraction poe;
	private final Date currentTime;
	private final ValidationPolicy policy;
	private final Context context;

	private Indication indication;
	private SubIndication subIndication;

	public PastSignatureValidationCheck(XmlValidationProcessArchivalData result, SignatureWrapper signature, DiagnosticData diagnosticData,
			XmlBasicBuildingBlocks bbb, POEExtraction poe, Date currentTime, ValidationPolicy policy, Context context, LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.bbb = bbb;
		this.poe = poe;
		this.currentTime = currentTime;
		this.policy = policy;
		this.context = context;
	}

	@Override
	protected boolean process() {
		PastSignatureValidation psv = new PastSignatureValidation(signature, diagnosticData, bbb, poe, currentTime, policy, context);
		XmlPSV psvResult = psv.execute();
		bbb.setPSV(psvResult);
		bbb.setConclusion(psvResult.getConclusion());

		if (isValid(psvResult)) {
			return true;
		} else {
			indication = psvResult.getConclusion().getIndication();
			subIndication = psvResult.getConclusion().getSubIndication();
			return false;
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_IPSVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPSVC_ANS;
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
