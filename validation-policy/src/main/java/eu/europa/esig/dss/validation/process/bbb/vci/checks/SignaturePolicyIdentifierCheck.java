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
package eu.europa.esig.dss.validation.process.bbb.vci.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

public class SignaturePolicyIdentifierCheck extends AbstractMultiValuesCheckItem<XmlVCI> {

	private final SignatureWrapper signature;
	private final MultiValuesConstraint multiValues;

	public SignaturePolicyIdentifierCheck(XmlVCI result, SignatureWrapper signature, MultiValuesConstraint multiValues) {
		super(result, multiValues);
		this.signature = signature;
		this.multiValues = multiValues;
	}

	@Override
	protected boolean process() {
		String policyId = signature.getPolicyId();
		if (multiValues.getId().contains(SignaturePolicyType.NO_POLICY.name()) && Utils.isStringEmpty(policyId)) {
			return true;
		} else if (multiValues.getId().contains(SignaturePolicyType.ANY_POLICY.name()) && Utils.isStringNotEmpty(policyId)) {
			return true;
		} else if (multiValues.getId().contains(SignaturePolicyType.IMPLICIT_POLICY.name())
				&& Utils.areStringsEqual(SignaturePolicyType.IMPLICIT_POLICY.name(), policyId)) {
			return true;
		}
		// oids
		return processValueCheck(policyId);
	}

	@Override
	protected String getMessageTag() {
		return "BBB_VCI_ISPK";
	}

	@Override
	protected String getErrorMessageTag() {
		return "BBB_VCI_ISPK_ANS_1";
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.POLICY_PROCESSING_ERROR;
	}

}
