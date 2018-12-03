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

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class LongTermValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	private final XmlConstraintsConclusion longTermValidationResult;
	private Indication ltvIndication;
	private SubIndication ltvSubIndication;
	private List<XmlName> ltvErrors;

	public LongTermValidationCheck(XmlValidationProcessArchivalData result, XmlConstraintsConclusion longTermValidationResult, LevelConstraint constraint) {
		super(result, constraint);

		this.longTermValidationResult = longTermValidationResult;
	}

	@Override
	protected boolean process() {
		if (longTermValidationResult != null && longTermValidationResult.getConclusion() != null) {
			ltvIndication = longTermValidationResult.getConclusion().getIndication();
			ltvSubIndication = longTermValidationResult.getConclusion().getSubIndication();
			ltvErrors = longTermValidationResult.getConclusion().getErrors();

			return Indication.PASSED.equals(ltvIndication)
					|| (Indication.INDETERMINATE.equals(ltvIndication) && (SubIndication.REVOKED_NO_POE.equals(ltvSubIndication)
							|| SubIndication.REVOKED_CA_NO_POE.equals(ltvSubIndication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(ltvSubIndication)
							|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(ltvSubIndication)));
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
	protected List<XmlName> getPreviousErrors() {
		return ltvErrors;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return ltvIndication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return ltvSubIndication;
	}

}
