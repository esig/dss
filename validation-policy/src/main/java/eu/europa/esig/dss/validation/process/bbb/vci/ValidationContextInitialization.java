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
package eu.europa.esig.dss.validation.process.bbb.vci;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.BasicBuildingBlockDefinition;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyHashValidCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifiedCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifierCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.4 Validation context initialization This building block initializes the
 * validation constraints (chain constraints, cryptographic constraints,
 * signature elements constraints) and parameters (X.509 validation parameters
 * including trust anchors, certificate validation data) that will be used to
 * validate the signature.
 */
public class ValidationContextInitialization extends Chain<XmlVCI> {

	private final SignatureWrapper signature;

	private final Context context;
	private final ValidationPolicy validationPolicy;

	public ValidationContextInitialization(SignatureWrapper signature, Context context, ValidationPolicy validationPolicy) {
		super(new XmlVCI());
		result.setTitle(BasicBuildingBlockDefinition.VALIDATION_CONTEXT_INITIALIZATION.getTitle());

		this.signature = signature;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {
		MultiValuesConstraint signaturePolicyConstraint = validationPolicy.getSignaturePolicyConstraint(context);

		ChainItem<XmlVCI> item = firstItem = signaturePolicyIdentifier(signaturePolicyConstraint);

		if (signature.isPolicyPresent()
				&& (!SignaturePolicyType.IMPLICIT_POLICY.name().equals(signature.getPolicyId()))) {
			item = item.setNextItem(signaturePolicyIdentified());

			item = item.setNextItem(signaturePolicyHashValid());
		}

	}

	private ChainItem<XmlVCI> signaturePolicyIdentifier(MultiValuesConstraint signaturePolicyConstraint) {
		return new SignaturePolicyIdentifierCheck(result, signature, signaturePolicyConstraint);
	}

	private ChainItem<XmlVCI> signaturePolicyIdentified() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyIdentifiedConstraint(context);
		return new SignaturePolicyIdentifiedCheck(result, signature, constraint);
	}

	private ChainItem<XmlVCI> signaturePolicyHashValid() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyPolicyHashValid(context);
		return new SignaturePolicyHashValidCheck(result, signature, constraint);
	}

}
