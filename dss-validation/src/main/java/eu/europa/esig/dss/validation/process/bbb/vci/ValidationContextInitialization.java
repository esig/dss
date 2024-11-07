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
package eu.europa.esig.dss.validation.process.bbb.vci;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyHashValidCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifiedCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifierCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyStoreCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyZeroHashCheck;

/**
 * 5.2.4 Validation context initialization This building block initializes the
 * validation constraints (chain constraints, cryptographic constraints,
 * signature elements constraints) and parameters (X.509 validation parameters
 * including trust anchors, certificate validation data) that will be used to
 * validate the signature.
 */
public class ValidationContextInitialization extends Chain<XmlVCI> {

	/** The signature to validate */
	private final SignatureWrapper signature;

	/** The validation context */
	private final Context context;

	/** The validation policy */
	private final ValidationPolicy validationPolicy;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param signature {@link SignatureWrapper}
	 * @param context {@link Context}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public ValidationContextInitialization(I18nProvider i18nProvider, SignatureWrapper signature, Context context,
										   ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlVCI());
		this.signature = signature;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.VALIDATION_CONTEXT_INITIALIZATION;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlVCI> item = firstItem = signaturePolicyIdentifier();

		if (signature.isPolicyPresent() && (!SignaturePolicyType.IMPLICIT_POLICY.name().equals(signature.getPolicyId()))) {
			
			item = item.setNextItem(signaturePolicyIdentified());
			
			item = item.setNextItem(signaturePolicyStorePresent());

			// Compare hash only when a policy is identified
			if (signature.isPolicyIdentified()) {

				if (!signature.isPolicyZeroHash()) {
					item = item.setNextItem(signaturePolicyHashValid());
				} else {
					item = item.setNextItem(signaturePolicyZeroHash());
				}

			}
			
		}

	}

	private ChainItem<XmlVCI> signaturePolicyIdentifier() {
		MultiValuesConstraint signaturePolicyConstraint = validationPolicy.getSignaturePolicyConstraint(context);
		return new SignaturePolicyIdentifierCheck(i18nProvider, result, signature, signaturePolicyConstraint);
	}

	private ChainItem<XmlVCI> signaturePolicyIdentified() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyIdentifiedConstraint(context);
		return new SignaturePolicyIdentifiedCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlVCI> signaturePolicyStorePresent() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyStorePresentConstraint(context);
		return new SignaturePolicyStoreCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlVCI> signaturePolicyHashValid() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyPolicyHashValid(context);
		return new SignaturePolicyHashValidCheck(i18nProvider, result, signature, constraint);
	}

	private ChainItem<XmlVCI> signaturePolicyZeroHash() {
		return new SignaturePolicyZeroHashCheck(i18nProvider, result, signature, getWarnLevelConstraint());
	}

}
