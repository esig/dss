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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AdESAcceptableCheck extends ChainItem<XmlValidationSignatureQualification> {

	private final XmlConclusion etsi319102Conclusion;

	private MessageTag error;

	public AdESAcceptableCheck(XmlValidationSignatureQualification result, XmlConclusion etsi319102Conclusion, LevelConstraint constraint) {
		super(result, constraint);

		this.etsi319102Conclusion = etsi319102Conclusion;
	}

	@Override
	protected boolean process() {
		boolean valid = isValidConclusion(etsi319102Conclusion);
		if (!valid) {
			if (isIndeterminateConclusion(etsi319102Conclusion)) {
				error = MessageTag.QUAL_IS_ADES_IND;
			} else if (isInvalidConclusion(etsi319102Conclusion)) {
				error = MessageTag.QUAL_IS_ADES_INV;
			}
			return false;
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_IS_ADES;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return error;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return etsi319102Conclusion.getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return etsi319102Conclusion.getSubIndication();
	}

}
