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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;

import java.util.Date;
import java.util.Map;

/**
 * Checks if the past signature validation result is acceptable
 */
public class PastSignatureValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	/** The validated signature */
	private final SignatureWrapper signature;

	/** Map of all BBBs */
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	/** POE container */
	private final POEExtraction poe;

	/** Validation time */
	private final Date currentTime;

	/** Validation policy */
	private final ValidationPolicy policy;

	/** Validation context */
	private final Context context;

	/** Indication */
	private Indication indication;

	/** SubIndication */
	private SubIndication subIndication;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessArchivalData}
	 * @param signature {@link SignatureWrapper}
	 * @param bbbs map of all BBBs
	 * @param poe {@link POEExtraction}
	 * @param currentTime {@link Date}
	 * @param policy {@link ValidationPolicy}
	 * @param context {@link Context}
	 * @param constraint {@link LevelConstraint}
	 */
	public PastSignatureValidationCheck(I18nProvider i18nProvider, XmlValidationProcessArchivalData result,
										SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs,
										POEExtraction poe, Date currentTime, ValidationPolicy policy, Context context,
										LevelConstraint constraint) {
		super(i18nProvider, result, constraint, signature.getId());

		this.signature = signature;
		this.bbbs = bbbs;
		this.poe = poe;
		this.currentTime = currentTime;
		this.policy = policy;
		this.context = context;
	}

	@Override
	protected boolean process() {
		XmlBasicBuildingBlocks tokenBBB = bbbs.get(signature.getId());
		PastSignatureValidation psv = new PastSignatureValidation(i18nProvider, signature, bbbs, poe, currentTime, policy, context);
		XmlPSV psvResult = psv.execute();
		tokenBBB.setPSV(psvResult);
		tokenBBB.setConclusion(psvResult.getConclusion());

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
