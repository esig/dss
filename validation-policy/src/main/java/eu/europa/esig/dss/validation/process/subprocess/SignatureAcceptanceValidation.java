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

import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.Constraint;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.SignatureCryptographicConstraint;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ValidationXPathQueryHolder;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.x509.TimestampType;


/**
 * 5.5 Signature Acceptance Validation (SAV)
 * 5.5.1 Description
 * This building block covers any additional verification that shall be performed on the attributes/properties of the signature.
 *
 * 5.5.2 Inputs
 * Table 10: Inputs to the SVA process
 * - Input                                Requirement
 * - Signature                            Mandatory
 * - Cryptographic verification output    Optional
 * - Cryptographic Constraints            Optional
 * - Signature Constraints                Optional
 *
 * 5.5.3 Outputs
 * The process outputs one of the following indications:
 * Table 11: Outputs of the SVA process
 * - Indication: VALID
 * - Description: The signature is conformant with the validation constraints.
 *
 * - Indication: INVALID.SIG_CONSTRAINTS_FAILURE
 * - Description: The signature is not conformant with the validation constraints.
 * - Additional data items: The process shall output:
 * • The set of constraints that are not verified by the signature.
 * - Indication: INDETERMINATE.CRYPTO_CONSTRAINTS_FAILURE_NO_POE
 * - Description: At least one of the algorithms used in validation of the signature together with the size of the key, if applicable, used with that algorithm is no longer
 * considered reliable.
 * - Additional data items: The process shall output:
 * • A list of algorithms, together with the size of the key, if applicable, that have been used in validation of the signature but no longer are considered reliable together
 * with a time up to which each of the listed algorithms were considered secure.
 *
 */
public class SignatureAcceptanceValidation {

	/**
	 * The following variables are used only in order to simplify the writing of the rules!
	 */

	/**
	 * See {@link ProcessParameters#getCurrentValidationPolicy()}
	 */
	private ValidationPolicy constraintData;

	/**
	 * See {@link ProcessParameters#getCurrentTime()}
	 */
	private Date currentTime;

	/**
	 * See {@link ProcessParameters#getSignatureContext()}
	 */
	private XmlDom signatureContext;

	/**
	 * This node is used to add the constraint nodes.
	 */
	private XmlNode subProcessNode;

	private void prepareParameters(final ProcessParameters params) {

		this.constraintData = params.getCurrentValidationPolicy();
		this.signatureContext = params.getSignatureContext();
		this.currentTime = params.getCurrentTime();

		isInitialised();
	}

	private void isInitialised() {

		if (constraintData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (signatureContext == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signatureContext"));
		}
		if (currentTime == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "currentTime"));
		}
	}

	/**
	 * 5.5.4 Processing
	 * This process consists in checking the Signature and Cryptographic Constraints against the signature. The
	 * general principle is as follows: perform the following for each constraint:
	 *
	 * • If the constraint necessitates processing a property/attribute in the signature, perform the processing of
	 * the property/attribute as specified from clause 5.5.4.1 to 5.5.4.8.
	 *
	 * 5.5.4.1 Processing AdES properties/attributes This clause describes the application of Signature Constraints on
	 * the content of the signature including the processing on signed and unsigned properties/attributes.
	 * Constraint XML description:
	 * <SigningCertificateChainConstraint><br>
	 * <MandatedSignedQProperties>
	 *
	 * Indicates the mandated signed qualifying properties that are mandated to be present in the signature.
	 *
	 * This method prepares the execution of the SAV process.
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
		 * 5.5 Signature Acceptance Validation (SAV)
		 */
		subProcessNode = processNode.addChild(NodeName.SAV);

		final Conclusion conclusion = process(params);

		final XmlNode conclusionXmlNode = conclusion.toXmlNode();
		subProcessNode.addChild(conclusionXmlNode);
		return conclusion;
	}

	/**
	 * This method implement SAV process.
	 *
	 * @param params validation process parameters
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion process(final ProcessParameters params) {

		final Conclusion conclusion = new Conclusion();

		// structural validation (only for XAdES)
		if (!checkStructuralValidationConstraint(conclusion)) {
			return conclusion;
		}

		/**
		 * 5.5.4.1 Processing AdES properties/attributes
		 * This clause describes the application of Signature Constraints on the content of the signature including the processing
		 *on signed and unsigned properties/attributes.
		 */
		// signing-time
		if (!checkSigningTimeConstraint(conclusion)) {
			return conclusion;
		}

		// content-type
		if (!checkContentTypeConstraint(conclusion)) {
			return conclusion;
		}

		// content-hints
		if (!checkContentHintsConstraint(conclusion)) {
			return conclusion;
		}

		// content-reference
		// TODO: (Bob: 2014 Mar 07)

		// content-identifier
		if (!checkContentIdentifierConstraint(conclusion)) {
			return conclusion;
		}

		// commitment-type-indication
		if (!checkCommitmentTypeIndicationConstraint(conclusion)) {
			return conclusion;
		}

		// signer-location
		if (!checkSignerLocationConstraint(conclusion)) {
			return conclusion;
		}

		// signer-attributes
		// TODO: (Bob: 2014 Mar 08)

		// content-time-stamp
		if (!checkContentTimeStampConstraints(conclusion)) {
			return conclusion;
		}

		/*if (!checkCounterSignatureConstraints(conclusion)) {
			return conclusion;
		}*/

		/**
		 * <MandatedUnsignedQProperties>
		 *
		 * ../..
		 *
		 * <OnRoles>
		 */
		if (!checkClaimedRoleConstraint(conclusion)) {
			return conclusion;
		}

		/**
		 * 5.5.4.2 Processing signing certificate reference constraint
		 * If the SigningCertificate property contains references to other certificates in the path, the verifier shall check
		 * each of the certificates in the certification path against these references as specified in steps 1 and 2 in clause 5.1.4.1
		 * (resp clause 5.1.4.2) for XAdES (resp CAdES).
		 * Should this property contain one or more references to certificates other than those present in the certification path, the
		 * verifier shall assume that a failure has occurred during the verification.
		 * Should one or more certificates in the certification path not be referenced by this property, the verifier shall assume that
		 * the verification is successful unless the signature policy mandates that references to all the certificates in the
		 * certification path "shall" be present.
		 *
		 * // TODO: (Bob: 2014 Mar 07) This is not yet implemented.
		 *
		 * 5.5.4.3 Processing claimed signing time
		 * If the signature constraints contain constraints regarding this property, the verifying application shall
		 * follow its rules for checking this signed property. Otherwise, the verifying application shall make the value
		 * of this property/attribute available to its DA, so that it may decide additional suitable processing, which is
		 * out of the scope of the present document.
		 *
		 * ../..
		 */

		/**
		 * 5.5.4.6 Processing Time-stamps on signed data objects<br>
		 * If the signature constraints contain specific constraints for content-time-stamp attributes, the SVA shall
		 * check that they are satisfied. To do so, the SVA shall do the following steps for each content-time-stamp
		 * attribute:<br>
		 * 1) Perform the Validation Process for AdES Time-Stamps as defined in clause 7 with the time-stamp token of the
		 * content-time-stamp attribute.<br>
		 * 2) Check the message imprint: check that the hash of the signed data obtained using the algorithm indicated in
		 * the time-stamp token matches the message imprint indicated in the token.<br>
		 * 3) Apply the constraints for content-time-stamp attributes to the results returned in the previous steps. If
		 * any check fails, return INVALID/SIG_CONSTRAINTS_FAILURE with an explanation of the unverified constraint.
		 */

		/**
		 5.5.4.7 Processing Countersignatures
		 If the signature constraints define specific constraints for countersignature attributes, the SVA shall check that they are
		 satisfied. To do so, the SVA shall do the following steps for each countersignature attribute:
		 1) Perform the validation process for AdES-BES/EPES using the countersignature in the property/attribute and
		 the signature value octet string of the signature as the signed data object.
		 2) Apply the constraints for countersignature attributes to the result returned in the previous step. If any check
		 fails, return INVALID/SIG_CONSTRAINTS_FAILURE with an explanation of the unverified constraint.
		 If the signature constraints do not contain any constraint on countersignatures, the SVA may still verify the
		 countersignature and provide the results in the validation report. However, it shall not consider the signature validation
		 to having failed if the countersignature could not be verified.
		 */

		/**
		 *
		 5.5.4.8 Processing signer attributes/roles
		 If the signature constraints define specific constraints for certified attributes/roles, the SVA shall perform the following
		 checks:
		 1) The SVA shall verify the validity of the attribute certificate(s) present in this property/attribute following the
		 rules established in [6].
		 2) The SVA shall check that the attribute certificate(s) actually match the rules specified in the input constraints.
		 If the signature rules do not specify rules for certified attributes/roles, the SVA shall make the value of this
		 property/attribute available to its DA so that it may decide additional suitable processing, which is out of the scope of
		 the present document.
		 */

		// TODO: (Bob: 2014 Mar 23) To be converted to the WARNING system
		final boolean checkIfCertifiedRoleIsPresent = constraintData.shouldCheckIfCertifiedRoleIsPresent();
		if (checkIfCertifiedRoleIsPresent) {

			final XmlNode constraintNode = addConstraint(MessageTag.BBB_SAV_ICERRM);

			final List<String> requestedCertifiedRoles = constraintData.getCertifiedRoles();
			final String requestedCertifiedRolesString = RuleUtils.toString(requestedCertifiedRoles);

			final List<XmlDom> certifiedRolesXmlDom = signatureContext.getElements("./CertifiedRoles/CertifiedRole");
			final List<String> certifiedRoles = XmlDom.convertToStringList(certifiedRolesXmlDom);
			final String certifiedRolesString = RuleUtils.toString(certifiedRoles);

			boolean contains = RuleUtils.contains(requestedCertifiedRoles, certifiedRoles);

			if (!contains) {

				constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
				conclusion.setIndication(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE);
				conclusion.addError(MessageTag.BBB_SAV_ICERRM_ANS).setAttribute(AttributeName.CERTIFIED_ROLES, certifiedRolesString).setAttribute(AttributeName.REQUESTED_ROLES, requestedCertifiedRolesString);
				return conclusion;
			}
			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);
			constraintNode.addChild(NodeName.INFO, certifiedRolesString).setAttribute(AttributeName.FIELD, AttributeName.CERTIFIED_ROLES);
			constraintNode.addChild(NodeName.INFO, "WARNING: The attribute certificate is not cryptographically validated.");
		}

		// Main signature cryptographic constraints validation
		if (!checkMainSignatureCryptographicConstraint(conclusion)) {
			return conclusion;
		}

		// This validation process returns VALID
		conclusion.setIndication(Indication.VALID);
		return conclusion;
	}

	/**
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final MessageTag messageTag) {

		final XmlNode constraintNode = subProcessNode.addChild(NodeName.CONSTRAINT);
		constraintNode.addChild(NodeName.NAME, messageTag.getMessage()).setAttribute(AttributeName.NAME_ID, messageTag.name());
		return constraintNode;
	}

	/**
	 * Check of structural validation (only for XAdES signature: XSD schema validation)
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkStructuralValidationConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getStructuralValidationConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISSV);
		final boolean structureValid = signatureContext.getBoolValue("./StructuralValidation/Valid/text()");
		constraint.setValue(structureValid);
		final String message = signatureContext.getValue("./StructuralValidation/Message/text()");
		if (StringUtils.isNotBlank(message)) {
			constraint.setAttribute("Log", message);
		}
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISSV_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of signing-time
	 *
	 * 5.5.4.3 Processing claimed signing time
	 * If the signature constraints contain constraints regarding this property, the verifying application shall follow its rules for
	 * checking this signed property.
	 * Otherwise, the verifying application shall make the value of this property/attribute available to its DA, so that it may
	 * decide additional suitable processing, which is out of the scope of the present document.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSigningTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSigningTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPSTP);
		final String signingTime = signatureContext.getValue("./DateTime/text()");
		constraint.setValue(StringUtils.isNotBlank(signingTime));
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPSTP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of content-type (signed property)
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkContentTypeConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getContentTypeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPCTP);
		final String contentType = signatureContext.getValue("./ContentType/text()");
		constraint.setValue(contentType);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPCTP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of content-hints
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkContentHintsConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getContentHintsConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPCHP);
		final String contentHints = signatureContext.getValue("./ContentHints/text()");
		constraint.setValue(contentHints);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPCHP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of content-identifier
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkContentIdentifierConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getContentIdentifierConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPCIP);
		final String contentIdentifier = signatureContext.getValue("./ContentIdentifier/text()");
		constraint.setValue(contentIdentifier);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPCIP_ANS);
		//constraint.setAttribute()
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of commitment-type-indication
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkCommitmentTypeIndicationConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getCommitmentTypeIndicationConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPXTIP);
		// TODO: A set of commitments must be checked
		final String commitmentTypeIndicationIdentifier = signatureContext.getValue("./CommitmentTypeIndication/Identifier[1]/text()");
		constraint.setValue(commitmentTypeIndicationIdentifier);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPXTIP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.checkInList();
	}

	/**
	 * Check of signer-location
	 *
	 * 5.5.4.5 Processing indication of production place of the signature
	 * If the signature constraints contain constraints regarding this property, the verifying application shall follow its rules for
	 * checking this signed property.
	 * Otherwise, the verifying application shall make the value of this property/attribute available to its DA, so that it may
	 * decide additional suitable processing, which is out of the scope of the present document.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSignerLocationConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSignerLocationConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPSLP);
		String signatureProductionPlace = signatureContext.getValue("./SignatureProductionPlace/text()");
		final XmlDom signProductionPlaceXmlDom = signatureContext.getElement("./SignatureProductionPlace");
		if (signProductionPlaceXmlDom != null) {

			final List<XmlDom> elements = signProductionPlaceXmlDom.getElements("./*");
			for (final XmlDom element : elements) {

				if (!signatureProductionPlace.isEmpty()) {

					signatureProductionPlace += "; ";
				}
				signatureProductionPlace += element.getName() + ": " + element.getText();
			}
		}
		constraint.setValue(signatureProductionPlace);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPSLP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of content-time-stamp: verifies whether a content-timestamp (or similar) element is present
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkContentTimeStampConstraints(final Conclusion conclusion) {

		final Constraint constraint1 = constraintData.getContentTimestampPresenceConstraint();
		if (constraint1 == null) {
			return true;
		}
		constraint1.create(subProcessNode, MessageTag.BBB_SAV_ISQPCTSIP);

		//get count of all possible content timestamps
		long count = signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.CONTENT_TIMESTAMP);
		count += signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		count += signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);

		final String countValue = count <= 0 ? "" : String.valueOf(count);
		constraint1.setValue(countValue);
		constraint1.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPCTSIP_ANS);
		constraint1.setConclusionReceiver(conclusion);

		final Constraint constraint2 = constraintData.getContentTimestampImprintFoundConstraint();
		if (constraint2 == null) {
			return constraint1.check();
		}
		constraint2.create(subProcessNode, MessageTag.ADEST_IMIDF);
		constraint2.setValue(true);
		constraint2.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.ADEST_IMIDF_ANS);
		constraint2.setConclusionReceiver(conclusion);

		final Constraint constraint3 = constraintData.getContentTimestampImprintIntactConstraint();
		if (constraint3 == null) {
			return constraint1.check() && constraint2.check();
		}
		constraint3.create(subProcessNode, MessageTag.ADEST_IMIVC);
		constraint3.setValue(true);
		constraint3.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.ADEST_IMIVC_ANS);
		constraint3.setConclusionReceiver(conclusion);

		return constraint1.check() && constraint2.check() && constraint3.check();
	}

	/**
	 * @param conclusion
	 * @return
	 */
	private boolean checkContentTimestampImprintFoundConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getContentTimestampPresenceConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ISQPCTSIP);

		//get all possible content timestamps
		long count = signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.CONTENT_TIMESTAMP);
		count += signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		count += signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);

		final String countValue = count <= 0 ? "" : String.valueOf(count);
		constraint.setValue(countValue);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ISQPCTSIP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of unsigned qualifying property: claimed roles
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkClaimedRoleConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getClaimedRoleConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.BBB_SAV_ICRM);
		final List<XmlDom> claimedRolesXmlDom = signatureContext.getElements("./ClaimedRoles/ClaimedRole");
		final List<String> claimedRoles = XmlDom.convertToStringList(claimedRolesXmlDom);
		// TODO (Bob) to be implemented fro each claimed role. Attendance must be taken into account.
		final String attendance = constraintData.getCertifiedRolesAttendance();
		String claimedRole = null;
		for (String claimedRole_ : claimedRoles) {

			claimedRole = claimedRole_;
			break;
		}
		if ("ANY".equals(attendance)) {
			constraint.setExpectedValue("*");
		}
		constraint.setValue(claimedRole);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_SAV_ICRM_ANS);
		constraint.setConclusionReceiver(conclusion);
		boolean check = constraint.checkInList();
		return check;
	}

	/**
	 * Check of: main signature cryptographic verification
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkMainSignatureCryptographicConstraint(final Conclusion conclusion) {

		final SignatureCryptographicConstraint constraint = constraintData.getSignatureCryptographicConstraint(NodeName.MAIN_SIGNATURE);
		if (constraint == null) {
			return true;
		}
		constraint.create(subProcessNode, MessageTag.ASCCM);
		constraint.setCurrentTime(currentTime);
		constraint.setEncryptionAlgorithm(signatureContext.getValue(ValidationXPathQueryHolder.XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN));
		constraint.setDigestAlgorithm(signatureContext.getValue(ValidationXPathQueryHolder.XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN));
		constraint.setKeyLength(signatureContext.getValue(ValidationXPathQueryHolder.XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, MessageTag.EMPTY);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

}
