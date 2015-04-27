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
package eu.europa.esig.dss.validation.process.subprocess;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.SignaturePolicyConstraint;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * 5.2 Validation Context Initialization (VCI)<br/>
 * 5.2.1 Description<br/>
 * This process consists in initializing the validation constraints (chain constraints, cryptographic constraints, signature
 * constraints) and parameters (X.509 validation parameters, certificate meta-data) that will be used to validate the
 * signature. The constraints and parameters may be initialized from any of the sources listed in clauses 4.2, 4.3 and 4.4.<br/>
 * 5.2.2 Inputs<br/>
 * Table 4: Inputs to the VCI process<br/>
 * - Input                          Requirement<br/>
 * - Signature                      Mandatory<br/>
 * - Signature Validation Policies  Optional<br/>
 * - Trusted-status Service Lists   Optional<br/>
 * - Local configuration            Optional<br/>
 * 5.2.3 Outputs<br/>
 * In case of failure, the process outputs INDETERMINATE or INVALID with an indication explaining the reason(s) of failure.<br/>
 * In case of success, the process outputs the following:<br/>
 * Table 5: Output of the VCI process<br/>
 * - Output<br/>
 * - X.509 Validation Parameters<br/>
 * - Certificate meta-data<br/>
 * - Chain Constraints<br/>
 * - Cryptographic Constraints<br/>
 * - Signature Constraints<br/>
 *
 */
public class ValidationContextInitialisation {

	/**
	 * See {@link ProcessParameters#getDiagnosticData()}
	 */
	private XmlDom diagnosticData;

	/**
	 * See {@link ProcessParameters#getCurrentValidationPolicy()}
	 */
	private ValidationPolicy constraintData;

	/**
	 * See {@link ProcessParameters#getSignatureContext()}
	 */
	private XmlDom signatureContext;

	/**
	 * This node is used to add the constraint nodes.
	 */
	private XmlNode subProcessNode;

	private void prepareParameters(final ProcessParameters params) {

		this.diagnosticData = params.getDiagnosticData();
		this.constraintData = params.getCurrentValidationPolicy();
		this.signatureContext = params.getSignatureContext();

		isInitialised();
	}

	private void isInitialised() {

		if (diagnosticData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (signatureContext == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signatureContext"));
		}
	}

	/**
	 * This method prepares the execution of the VCI process.
	 *
	 * @param params      validation process parameters
	 * @param processNode the parent process {@code XmlNode} to use to include the validation information
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	public Conclusion run(final ProcessParameters params, final XmlNode processNode) {

		if (processNode == null) {

			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "processNode"));
		}
		prepareParameters(params);

		/**
		 * 5.2. Validation Context Initialisation (VCI)
		 */

		subProcessNode = processNode.addChild(NodeName.VCI);

		final Conclusion conclusion = process(params);

		final XmlNode conclusionXmlNode = conclusion.toXmlNode();
		subProcessNode.addChild(conclusionXmlNode);
		return conclusion;
	}

	/**
	 * This method implements VCI process.
	 *
	 * @param params validation process parameters
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion process(final ProcessParameters params) {

		final Conclusion conclusion = new Conclusion();

		/**
		 * 5.2.4 Processing
         If the validation constraints and parameters have been initialized using an allowed set of signature validation policies
         [i.2], [i.3] and if the signature has been created under one of these policies and also contains a commitment type
         indication property/attribute, the specific commitment defined in the policy shall be selected using this attribute. The
         clauses below describe the processing of these properties/attributes. The processing of additional sources for
         initialization (e.g. local configuration) is out of the scope of the present document.
         This implies that a signature policy referenced in a signature shall be known to the verifier and listed in the set of
         acceptable policies. If the policy is unknown to the verifier, accepting a commitment type is not possible and may even
         be dangerous. In this case, the SVA shall return INVALID/UNKNOWN_COMMITMENT_TYPE.
         If the SVA cannot access a formal policy, the policy is not able to parse the policy file or the SVA cannot process the
         policy for any other reason, it shall return INVALID/POLICY_PROCESSING_ERROR with an appropriate indication.
         If the SVA cannot identify the policy to use, it shall return INDETERMINATE/ NO_POLICY.
         5.2.4.1 Processing commitment type indication
         If this signed property is present, it allows identifying the commitment type and thus affects all rules for validation,
         which depend on the commitment type that shall be used in the validation context initialization.
         ETSI
         21 ETSI TS 102 853 V1.1.2 (2012-10)
         5.2.4.1.1 XAdES Processing
         If the signature is a XAdES signature, the SVA shall check that each xades:ObjectReference element within
         the xades:CommitmentTypeIndication actually references a ds:Reference element present in the
         signature. If any of these elements does not refer to one of the ds:Reference elements, then the SVA shall assume
         that a format failure has occurred during the verification and return INVALID/FORMAT_FAILURE with an indication
         that the validation failed to an invalid commitment type property.
		 */

		/**
		 * info:<br>
		 * There may be situation were a signer wants to explicitly indicate to a verifier that by signing the data, it
		 * illustrates a type of commitment on behalf of the signer. The commitmentTypeIndication attribute conveys such
		 * information.
		 */

		if (!checkSignaturePolicyIdentifier(conclusion)) {
			return conclusion;
		}

		// This validation process returns VALID
		conclusion.setIndication(Indication.VALID);
		return conclusion;
	}

	/**
	 * 5.2.4.2 Processing Signature Policy Identifier<br/>
	 * If this signed property/attribute is present and it is not implied, the SVA shall perform the following checks. If any of
	 * these checks fail, then the SVA shall assume that a failure has occurred during the verification and return INVALID/
	 * POLICY_PROCESSING_ERROR with an indication that the validation failed to an invalid signature policy identifier
	 * property/attribute.<br/>
	 * 1) Retrieve the electronic document containing the details of the policy, and identified by the contents of the
	 * property/attribute.<br/>
	 * 2) If the signature is a XAdES signature, apply the transformations indicated in the ds:Transforms element
	 * of xades:SignaturePolicyId element. If the signature is not a XAdES signature, go to step 3.<br/>
	 * 3) Obtain the digest of the resulting document against which the digest value present in the property/attribute will
	 * be checked:<br/>
	 * a) If the resulting document is based on TR 102 272 [i.2], use the digest value present in the
	 * SignPolicyDigest element from the resulting document. Check that the digest algorithm indicated
	 * in the SignPolicyDigestAlg from the resulting document is equal to the digest algorithm
	 * indicated in the property.<br/>
	 * b) If the resulting document is based on TR 102 038 [i.3], use the digest value present in
	 * signPolicyHash element from the resulting document. Check that the digest algorithm indicated in
	 * the signPolicyHashAlg from the resulting document is equal to the digest algorithm indicated in the
	 * attribute.<br/>
	 * c) In all other cases, compute the digest using the digesting algorithm indicated in the children of the
	 * property/attribute.<br/>
	 * 4) Check that the digest obtained in the previous step is equal to the digest value indicated in the children of the
	 * property/attribute.<br/>
	 * 5) Should the property/attribute have qualifiers, manage them according to the rules that are stated by the policy
	 * applying within the specific scenario.<br/>
	 * 6) If the checks described before end successfully, the process extracts the validation constraints from the rules
	 * encoded in the validation policy. If an explicit commitment is identified, select the rules corresponding to this
	 * commitment in the signature. If the commitment is not recognized, the Verifier may select the rules dependant
	 * on other sources (e.g. the data being signed). The way used by the signature policy for presenting the rules and
	 * their description are out of the scope of the present document. TR 102 038 [i.3] specifies a "XML format for
	 * signature policies" that may be automatically processed.<br/>
	 * If the signature policy is implied, and stated so by the signature rules, the SVA shall perform the checks mandated by
	 * the implicit signature policy that shall be provided by the verifier by one of the methods described in clause 4.2.
	 * NOTE: An implicit policy can in the most general case either be established according to the minimum
	 * requirements by law or if being more constrained only be discovered in well known or pre-agreed
	 * (driving) application contexts.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSignaturePolicyIdentifier(final Conclusion conclusion) {

		// TODO: (Bob: 2014 Mar 10)  TOMORROW NEW PolicyConstraint class should be created

		final SignaturePolicyConstraint constraint = constraintData.getSignaturePolicyConstraint();
		if (constraint == null) {
			return true;
		}

		constraint.create(subProcessNode, MessageTag.BBB_VCI_ISPK);
		String policyId = signatureContext.getValue("./Policy/Id/text()");
		if (StringUtils.isBlank(policyId)) {
			policyId = SignaturePolicy.NO_POLICY;
		}
		constraint.setIdentifier(policyId);
		constraint.setPolicyValidity(signatureContext.getBoolValue("./Policy/Status/text()"));
		constraint.setProcessingError(signatureContext.getValue("./Policy/ProcessingError/text()"));
		constraint.setNotice(signatureContext.getValue("./Policy/Notice/text()"));

		constraint.setIndications(Indication.INDETERMINATE, SubIndication.NO_SIGNER_CERTIFICATE_FOUND, MessageTag.BBB_ICS_AIDNASNE_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}
}
