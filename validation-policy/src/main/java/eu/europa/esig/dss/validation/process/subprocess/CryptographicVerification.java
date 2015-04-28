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

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.Constraint;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ValidationXPathQueryHolder;
import eu.europa.esig.dss.validation.report.Conclusion;

/**
 * This class executes the cryptographic signature verification. It can be for the document signatures or timestamp
 * signatures...
 *
 * 5.4 Cryptographic Verification (CV)<br/>
 * <br/>
 * 5.4.1 Description<br/>
 * This process consists in verifying the integrity of the signed data by performing the cryptographic verifications.<br/>
 * 5.4.2 Inputs<br/>
 * Table 8: Inputs to the CV process<br/>
 * - Input                          Requirement<br/>
 * - Signature                      Mandatory<br/>
 * - Signer Certificate             Mandatory<br/>
 * - Validated certificate chain    Optional<br/>
 * - Signed data object(s)          Optional<br/>
 * NOTE: In most cases, the cryptographic verification requires only the signer's certificate and not the entire validated chain. However, for some algorithms the full chain may
 * be required (e.g. the case of DSS/DSA public keys which inherit their parameters from the issuer certificate).<br/>
 * 5.4.3 Outputs<br/>
 * The process outputs one of the following indications together with the associated validation report data:<br/>
 * Table 9: Outputs of the CV process<br/>
 * - Indication: VALID<br/>
 * - Description: The signature passed the cryptographic verification.<br/>
 * - Additional data items:<br/>
 * <br/>
 * - Indication: INVALID HASH_FAILURE<br/>
 * - Description: The hash of at least one of the signed data items does not match the corresponding hash value in the signature.<br/>
 * - Additional data items: The process should output:<br/>
 * - • The identifier (s) (e.g. an URI) of the signed data that caused the failure.<br/>
 * <br/>
 * - Indication: INVALID SIG_CRYPTO_FAILURE<br/>
 * - Description: The cryptographic verification of the signature value failed.<br/>
 * <br/>
 * - Indication: INDETERMINATE SIGNED_DATA_NOT_FOUND<br/>
 * - Description: Cannot obtain signed data.<br/>
 * - Additional data items: The process should output:<br/>
 * - • The identifier (s) (e.g. an URI) of the signed data that caused the failure.<br/>
 *
 *
 */
public class CryptographicVerification {

	/**
	 * See {@link ProcessParameters#getCurrentValidationPolicy()}
	 */
	private ValidationPolicy constraintData;

	private XmlDom contextElement;

	/**
	 * This node is used to add the constraint nodes.
	 */
	private XmlNode subProcessNode;

	private void prepareParameters(final ProcessParameters params) {

		this.constraintData = params.getCurrentValidationPolicy();
		this.contextElement = params.getContextElement();

		isInitialised();
	}

	private void isInitialised() {

		if (constraintData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (contextElement == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signature"));
		}
	}

	/**
	 * 5.4.4 Processing<br>
	 * The first and second steps as well as the Data To Be Signed depend on the signature type. The technical details on
	 * how to do this correctly are out of scope for the present document. See [10], [16], [12], [13], [14] and [15] for
	 * details:
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

		subProcessNode = processNode.addChild(NodeName.CV);

		final Conclusion conclusion = process(params);

		final XmlNode conclusionXmlNode = conclusion.toXmlNode();
		subProcessNode.addChild(conclusionXmlNode);
		return conclusion;
	}

	/**
	 * This method implement CV process.
	 *
	 * @param params validation process parameters
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion process(final ProcessParameters params) {

		final Conclusion conclusion = new Conclusion();

		if (!checkReferenceDataExistenceConstraint(conclusion)) {
			return conclusion;
		}

		if (!checkReferenceDataIntactConstraint(conclusion)) {
			return conclusion;
		}

		if (!checkSignatureIntactConstraint(conclusion)) {
			return conclusion;
		}
		// This validation process returns VALID
		conclusion.setIndication(Indication.VALID);
		return conclusion;
	}

	/**
	 * 1) Obtain the signed data objects(s) if not provided in the inputs (e.g. by dereferencing an URI present in the
	 * signature). If the signed data object (s) cannot be obtained, abort with the indication
	 * INDETERMINATE/SIGNED_DATA_NOT_FOUND.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkReferenceDataExistenceConstraint(Conclusion conclusion) {

		final Constraint constraint = constraintData.getReferenceDataExistenceConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_CV_IRDOF);
		final boolean referenceDataFound = contextElement.getBoolValue(ValidationXPathQueryHolder.XP_REFERENCE_DATA_FOUND);
		constraint.setValue(referenceDataFound);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.SIGNED_DATA_NOT_FOUND, MessageTag.BBB_CV_IRDOF_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * 2) Check the integrity of the signed data objects. In case of failure, abort the signature validation process
	 * with INVALID/HASH_FAILURE.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkReferenceDataIntactConstraint(Conclusion conclusion) {

		final Constraint constraint = constraintData.getReferenceDataIntactConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_CV_IRDOI);
		final boolean referenceDataIntact = contextElement.getBoolValue(ValidationXPathQueryHolder.XP_REFERENCE_DATA_INTACT);
		constraint.setValue(referenceDataIntact);
		constraint.setIndications(Indication.INVALID, SubIndication.HASH_FAILURE, MessageTag.BBB_CV_IRDOI_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * 3) Verify the cryptographic signature using the public key extracted from the signer's certificate in the
	 * chain, the signature value and the signature algorithm extracted from the signature. If this cryptographic
	 * verification outputs a success indication, terminate with VALID. Otherwise, terminate with
	 * INVALID/SIG_CRYPTO_FAILURE.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSignatureIntactConstraint(Conclusion conclusion) {

		final Constraint constraint = constraintData.getSignatureIntactConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_CV_ISI);
		final boolean signatureIntact = contextElement.getBoolValue(ValidationXPathQueryHolder.XP_SIGNATURE_INTACT);
		constraint.setValue(signatureIntact);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CRYPTO_FAILURE, MessageTag.BBB_CV_ISI_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}
}
