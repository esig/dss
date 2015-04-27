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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;
import eu.europa.esig.dss.validation.policy.rules.RuleConstant;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * This class represents a signature policy constraint.
 */
public class SignaturePolicyConstraint extends Constraint {

	/**
	 * This variable stores the used signature policy identifier. If no policy is used then it contains {@code NO_POLICY}, if the policy is implied then it contains {@code
	 * IMPLICIT_POLICY}, if the policy is absent then it contains {@code ANY_POLICY}.
	 */
	protected String identifier;

	/**
	 * This variable stores the signature policy validity in case the policy identifier references a policy file.
	 */
	protected Boolean policyValidity;

	/**
	 * This variable stores the signature policy processing error in case where an error has been encountered when  processing the signature validation policy.
	 */
	protected String processingError;

	/**
	 * This variable stores the signature policy notice if any.
	 */
	protected String notice;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public SignaturePolicyConstraint(final String level) {

		super(level);
	}

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(final String policyId) {
		this.identifier = policyId;
	}

	public Boolean getPolicyValidity() {
		return policyValidity;
	}

	public void setPolicyValidity(final Boolean policyValidity) {
		this.policyValidity = policyValidity;
	}

	public String getProcessingError() {
		return processingError;
	}

	public void setProcessingError(final String processingError) {
		this.processingError = processingError;
	}

	public String getNotice() {
		return notice;
	}

	public void setNotice(final String notice) {
		this.notice = notice;
	}

	/**
	 * This method carry out the validation of the constraint.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	@Override
	public boolean check() {

		if (ignore()) {

			node.addChild(NodeName.STATUS, NodeValue.IGNORED);
			return true;
		}
		if (inform()) {

			node.addChild(NodeName.STATUS, NodeValue.INFORMATION);
			node.addChild(NodeName.INFO, null, messageAttributes).setAttribute(AttributeName.EXPECTED_VALUE, expectedValue).setAttribute("ConstraintValue", identifier);
			return true;
		}
		if (!SignaturePolicy.IMPLICIT_POLICY.equals(identifier)) {

			if (SignaturePolicy.NO_POLICY.equals(identifier)) {

				if (!identifiers.contains(identifier)) {

					if (warn()) {

						node.addChild(NodeName.STATUS, NodeValue.WARN);
						node.addChild(NodeName.WARNING, MessageTag.BBB_VCI_ISPK_ANS_1).setAttribute(AttributeName.EXPECTED_VALUE, expectedValue);
						conclusion.addWarning(MessageTag.BBB_VCI_ISPK_ANS_1).setAttribute(AttributeName.EXPECTED_VALUE, expectedValue);
						return true;
					}
					node.addChild(NodeName.STATUS, NodeValue.KO);
					node.addChild(NodeName.ERROR, MessageTag.BBB_VCI_ISPK_ANS_1);
					conclusion.setIndication(Indication.INDETERMINATE, SubIndication.NO_POLICY);
					conclusion.addError(MessageTag.BBB_VCI_ISPK_ANS_1).setAttribute(AttributeName.EXPECTED_VALUE, expectedValue);
					return false;
				}
			} else {

				if (!identifiers.contains(RuleConstant.ANY_POLICY)) {

					if (!policyValidity) {

						if (warn()) {

							node.addChild(NodeName.STATUS, NodeValue.WARN);
							node.addChild(NodeName.WARNING, MessageTag.BBB_VCI_ISPK_ANS_2).setAttribute(NodeName.ERROR, processingError);
							final Conclusion.Warning warning = conclusion.addWarning(MessageTag.BBB_VCI_ISPK_ANS_2);
							warning.setAttribute(NodeName.ERROR, processingError);
							return true;
						}
						node.addChild(NodeName.STATUS, NodeValue.KO);
						node.addChild(NodeName.ERROR, MessageTag.BBB_VCI_ISPK_ANS_2);
						conclusion.setIndication(Indication.INDETERMINATE, SubIndication.POLICY_PROCESSING_ERROR);
						final Conclusion.Error error = conclusion.addError(MessageTag.BBB_VCI_ISPK_ANS_2);
						error.setAttribute(NodeName.ERROR, processingError);
						return false;
					}
					if (!identifiers.contains(identifier)) {

						if (warn()) {

							node.addChild(NodeName.STATUS, NodeValue.WARN);
							node.addChild(NodeName.WARNING, MessageTag.BBB_VCI_ISPK_ANS_3).setAttribute(NodeName.ERROR, processingError);
							final Conclusion.Warning warning = conclusion.addWarning(MessageTag.BBB_VCI_ISPK_ANS_3);
							warning.setAttribute(AttributeName.EXPECTED_VALUE, expectedValue).setAttribute("ConstraintValue", identifier);
							return true;
						}
						node.addChild(NodeName.STATUS, NodeValue.KO);
						node.addChild(NodeName.ERROR, MessageTag.BBB_VCI_ISPK_ANS_3);
						conclusion.setIndication(Indication.INDETERMINATE, SubIndication.NO_POLICY);
						final Conclusion.Error error = conclusion.addError(MessageTag.BBB_VCI_ISPK_ANS_3);
						error.setAttribute(AttributeName.EXPECTED_VALUE, expectedValue).setAttribute("ConstraintValue", identifier);
						return false;
					}
				}
			}
		}
		node.addChild(NodeName.STATUS, NodeValue.OK);
		final XmlNode info = node.addChild(NodeName.INFO);
		info.setAttribute(NodeName.IDENTIFIER, identifier);
		if (!notice.isEmpty()) {

			info.setAttribute(NodeName.NOTICE, notice);
		}
		return true;
	}
}

