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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.List;

/**
 * Checks if the signature's basic validation result is acceptable
 */
public class AcceptableBasicSignatureValidationCheck extends ChainItem<XmlValidationProcessLongTermData> {

	/** Signature's basic validation conclusion */
	private final XmlConstraintsConclusion basicSignatureValidation;

	/** The validation Indication */
	private Indication bbbIndication;

	/** The validation SubIndication */
	private SubIndication bbbSubIndication;

	/** The validation errors */
	private List<XmlName> bbbErrors;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessLongTermData}
	 * @param basicSignatureValidation {@link XmlConstraintsConclusion}
	 * @param constraint {@link LevelConstraint}
	 */
	public AcceptableBasicSignatureValidationCheck(I18nProvider i18nProvider, XmlValidationProcessLongTermData result, 
			XmlConstraintsConclusion basicSignatureValidation, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.basicSignatureValidation = basicSignatureValidation;
	}

	@Override
	protected boolean process() {
		if (basicSignatureValidation != null && basicSignatureValidation.getConclusion() != null) {
			XmlConclusion basicSignatureConclusion = basicSignatureValidation.getConclusion();
			bbbIndication = basicSignatureConclusion.getIndication();
			bbbSubIndication = basicSignatureConclusion.getSubIndication();
			bbbErrors = basicSignatureConclusion.getErrors();

			return ValidationProcessUtils.isAllowedBasicSignatureValidation(basicSignatureConclusion);
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.LTV_ABSV;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.LTV_ABSV_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return bbbIndication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return bbbSubIndication;
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return bbbErrors;
	}

}
