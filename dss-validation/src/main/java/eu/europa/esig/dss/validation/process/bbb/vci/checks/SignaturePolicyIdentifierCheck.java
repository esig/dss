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
package eu.europa.esig.dss.validation.process.bbb.vci.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignaturePolicyType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

/**
 * Checks if the signature policy identifier is acceptable
 */
public class SignaturePolicyIdentifierCheck extends AbstractMultiValuesCheckItem<XmlVCI> {

	/** The signature to check */
	private final SignatureWrapper signature;

	/** The constraint */
	private final MultiValuesConstraint multiValues;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlVCI}
	 * @param signature {@link SignatureWrapper}
	 * @param multiValues {@link MultiValuesConstraint}
	 */
	public SignaturePolicyIdentifierCheck(I18nProvider i18nProvider, XmlVCI result, SignatureWrapper signature,
										  MultiValuesConstraint multiValues) {
		super(i18nProvider, result, multiValues);
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
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VCI_ISPK;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VCI_ISPK_ANS;
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
