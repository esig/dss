/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Collections;
import java.util.List;

/**
 * Checks if the long-term validation check is acceptable
 */
public class LongTermValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	/** Long-term validation's conclusion */
	private final XmlConstraintsConclusion longTermValidationResult;

	/** LTV Indication */
	private Indication ltvIndication;

	/** LTV SubIndication */
	private SubIndication ltvSubIndication;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessArchivalData}
	 * @param longTermValidationResult {@link XmlConstraintsConclusion}
	 * @param constraint {@link LevelConstraint}
	 */
	public LongTermValidationCheck(I18nProvider i18nProvider, XmlValidationProcessArchivalData result, 
			XmlConstraintsConclusion longTermValidationResult, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.longTermValidationResult = longTermValidationResult;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.LTV;
	}

	@Override
	protected boolean process() {
		if (longTermValidationResult != null && longTermValidationResult.getConclusion() != null) {
			ltvIndication = longTermValidationResult.getConclusion().getIndication();
			ltvSubIndication = longTermValidationResult.getConclusion().getSubIndication();

			return ValidationProcessUtils.isAllowedValidationWithLongTermData(longTermValidationResult.getConclusion());
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ARCH_LTVV;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ARCH_LTVV_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return ltvIndication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return ltvSubIndication;
	}

	@Override
	protected List<XmlMessage> getPreviousErrors() {
		if (longTermValidationResult != null && longTermValidationResult.getConclusion() != null) {
			return longTermValidationResult.getConclusion().getErrors();
		}
		return Collections.emptyList();
	}

}
