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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.MessageTag;

public class AcceptableBasicSignatureValidationCheck extends ChainItem<XmlValidationProcessLongTermData> {

	private final XmlConstraintsConclusion basicSignatureValidation;

	private Indication bbbIndication;
	private SubIndication bbbSubIndication;
	private List<XmlName> bbbErrors;

	public AcceptableBasicSignatureValidationCheck(XmlValidationProcessLongTermData result, XmlConstraintsConclusion basicSignatureValidation,
			LevelConstraint constraint) {
		super(result, constraint);

		this.basicSignatureValidation = basicSignatureValidation;
	}

	@Override
	protected boolean process() {
		if (basicSignatureValidation != null && basicSignatureValidation.getConclusion() != null) {
			XmlConclusion basicSignatureConclusion = basicSignatureValidation.getConclusion();
			bbbIndication = basicSignatureConclusion.getIndication();
			bbbSubIndication = basicSignatureConclusion.getSubIndication();
			bbbErrors = basicSignatureConclusion.getErrors();

			boolean allowed = Indication.PASSED.equals(bbbIndication)
					|| (Indication.INDETERMINATE.equals(bbbIndication) && (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bbbSubIndication) || 
							SubIndication.REVOKED_NO_POE.equals(bbbSubIndication) || SubIndication.REVOKED_CA_NO_POE.equals(bbbSubIndication) || 
							SubIndication.TRY_LATER.equals(bbbSubIndication) ||SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bbbSubIndication)));

			return allowed;
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
