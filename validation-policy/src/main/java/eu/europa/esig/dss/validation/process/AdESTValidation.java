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
package eu.europa.esig.dss.validation.process;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.BasicValidationProcessValidConstraint;
import eu.europa.esig.dss.validation.policy.Constraint;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.TimestampValidationProcessValidConstraint;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * This class implements:<br>
 *
 * 8 Validation Process for AdES-T
 *
 * 8.1 Description<br>
 *
 * An AdES-T signature is built on BES or EPES signature and incorporates trusted time associated to the signature. The
 * trusted time may be provided by two different means:
 *
 * • A signature time-stamp unsigned property/attribute added to the electronic signature.
 *
 * • A time mark of the electronic signature provided by a trusted service provider.
 *
 * This clause describes a validation process for AdES-T signatures.
 *
 *
 */
public class AdESTValidation {

	private static final Logger LOG = LoggerFactory.getLogger(AdESTValidation.class);

	// Primary inputs
	/**
	 * See {@link eu.europa.esig.dss.validation.policy.ProcessParameters#getDiagnosticData()}
	 *
	 * @return
	 */
	private XmlDom diagnosticData;

	/**
	 * See {@link eu.europa.esig.dss.validation.policy.ProcessParameters#getValidationPolicy()}
	 *
	 * @return
	 */
	private ValidationPolicy constraintData;

	// Secondary inputs
	/**
	 * See {@link eu.europa.esig.dss.validation.policy.ProcessParameters#getCurrentTime()}
	 *
	 * @return
	 */
	private Date currentTime;

	/**
	 * See {@link eu.europa.esig.dss.validation.policy.ProcessParameters#getBvData()}
	 *
	 * @return
	 */
	private XmlDom basicValidationData;

	private XmlDom timestampValidationData; // Basic Building Blocks for timestamps

	// local helper variable
	private XmlNode conclusionNode;

	private XmlDom bvpConclusion;
	private String bvpIndication;
	private String bvpSubIndication;

	/**
	 * This node is used to add the constraint nodes.
	 */
	private XmlNode signatureXmlNode;

	/**
	 * Represents the {@code XmlDom} of the signature currently being validated
	 */
	private XmlDom signatureXmlDom;

	/**
	 * Represents the identifier of the signature currently being validated
	 */
	private String signatureId;

	/**
	 * Represents the {@code XmlDom} of the timestamp currently being validated
	 */
	private XmlNode timestampXmlNode;

	/**
	 * Represents the identifier of the timestamp currently being validated
	 */
	private String timestampId;

	private Date bestSignatureTime;

	private void prepareParameters(final XmlNode mainNode, final ProcessParameters params) {

		this.diagnosticData = params.getDiagnosticData();
		this.currentTime = params.getCurrentTime();
		isInitialised(mainNode, params);
	}

	/**
	 * Checks if each necessary data needed to carry out the validation process is present. The process can be called
	 * from different contexts. This method calls automatically the necessary sub processes to prepare all input data.
	 *
	 * @param params
	 */
	private void isInitialised(final XmlNode mainNode, final ProcessParameters params) {

		if (diagnosticData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (params.getValidationPolicy() == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (currentTime == null) {

			currentTime = new Date();
			params.setCurrentTime(currentTime);
		}
		if (basicValidationData == null) {

			/**
			 * The execution of the Basic Validation process which creates the basic validation data.<br>
			 */
			final BasicValidation basicValidation = new BasicValidation();
			basicValidationData = basicValidation.run(mainNode, params);
		}
		if (timestampValidationData == null) {

			/**
			 * This executes the Basic Building Blocks process for timestamps present in the signature.<br>
			 * This process needs the diagnostic and policy data. It creates the timestamps validation data.
			 */
			final TimestampValidation timeStampValidation = new TimestampValidation();
			timestampValidationData = timeStampValidation.run(mainNode, params);
		}
	}

	/**
	 * This method runs the AdES-T validation process.
	 *
	 * 8.2 Inputs<br>
	 * - Signature ..................... Mandatory<br>
	 * - Signed data object (s) ........ Optional<br>
	 * - Trusted-status Service Lists .. Optional<br>
	 * - Signature Validation Policies . Optional<br>
	 * - Local configuration ........... Optional<br>
	 * - Signer's Certificate .......... Optional<br>
	 *
	 * 8.3 Outputs<BR>
	 * The main output of the signature validation is a status indicating the validity of the signature. This status may
	 * be accompanied by additional information (see clause 4).
	 *
	 * 8.4 Processing<BR>
	 * The following steps shall be performed:
	 *
	 * @param params
	 * @return
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

		prepareParameters(mainNode, params);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		// This script is a validation process for AdES-T signatures.
		XmlNode adestValidationData = mainNode.addChild(NodeName.ADEST_VALIDATION_DATA);

		/**
		 * 1) Initialise the set of signature time-stamp tokens from the signature time-stamp properties/attributes
		 * present in the signature and initialise the best-signature-time to the current time.
		 *
		 * NOTE 1: Best-signature-time is an internal variable for the algorithm denoting the earliest time when it can be
		 * proven that a signature has existed.
		 */
		final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");
		for (final XmlDom signature : signatures) {

			signatureXmlDom = signature;
			signatureId = signature.getValue("./@Id");
			final String type = signature.getValue("./@Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {

				params.setCurrentValidationPolicy(params.getCountersignatureValidationPolicy());
			} else {

				params.setCurrentValidationPolicy(params.getValidationPolicy());
			}
			constraintData = params.getCurrentValidationPolicy();
			signatureXmlNode = adestValidationData.addChild(NodeName.SIGNATURE);
			signatureXmlNode.setAttribute(AttributeName.ID, signatureId);

			// current time
			bestSignatureTime = currentTime;

			final Conclusion conclusion = process();

			final XmlNode conclusionXmlNode = conclusion.toXmlNode();
			signatureXmlNode.addChild(conclusionXmlNode);
		}
		final XmlDom atvDom = adestValidationData.toXmlDom();
		params.setAdestData(atvDom);
		return atvDom;
	}

	/**
	 * 2)	Signature validation: Perform the validation process for BES signatures (see clause 6) with all the inputs, including the processing of any signed attributes/properties
	 * as specified. If this validation outputs VALID, INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, INDETERMINATE/REVOKED_NO_POE or INDETERMINATE/OUT_OF_BOUNDS_NO_POE, go to
	 * the next step. Otherwise, terminate with the returned status and information.	 *
	 *
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion process() {

		final Conclusion signatureConclusion = new Conclusion();

		bvpConclusion = basicValidationData.getElement("/" + NodeName.BASIC_VALIDATION_DATA + "/Signature[@Id='%s']/Conclusion", signatureId);
		bvpIndication = bvpConclusion.getValue("./Indication/text()");
		bvpSubIndication = bvpConclusion.getValue("./SubIndication/text()");

		if (!checkBasicValidationProcessConclusionConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		/**
		 * 3) Verification of time-marks: the verification of time-marks is out of the scope of the present document. If
		 * the SVA accepts a time-mark as trustworthy (based on out-of-band mechanisms) and if the indicated time is
		 * before the best-signature-time, set best-signature-time to the indicated time.
		 *
		 * --> The DSS framework does not handle the time-marks.
		 */

		// This is the list of acceptable timestamps
		final List<String> rightTimestamps = new ArrayList<String>();

		final List<XmlDom> timestamps = signatureXmlDom.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.SIGNATURE_TIMESTAMP);
		timestamps.addAll(signatureXmlDom.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.CONTENT_TIMESTAMP));
		timestamps.addAll(signatureXmlDom.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		timestamps.addAll(signatureXmlDom.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));

		boolean found = false;
		int noContentTimestampCount = 0;

		for (final XmlDom timestamp : timestamps) {

			// timestampX
			timestampId = timestamp.getValue("./@Id");
			final String timestampTypeString = timestamp.getValue("./@Type");
			final TimestampType timestampType = TimestampType.valueOf(timestampTypeString);
			final boolean contentTimestamp = isContentTimestamp(timestampType);
			final Date productionTime = timestamp.getTimeValue("./ProductionTime/text()");

			if (!contentTimestamp) {
				noContentTimestampCount++;
			}

			timestampXmlNode = signatureXmlNode.addChild(NodeName.TIMESTAMP);
			timestampXmlNode.setAttribute(AttributeName.ID, timestampId);
			timestampXmlNode.setAttribute(AttributeName.TYPE, timestampTypeString);
			timestampXmlNode.setAttribute(AttributeName.GENERATION_TIME, DSSUtils.formatDate(productionTime));

			final Conclusion timestampConclusion = new Conclusion();

			if (!checkMessageImprintDataFoundConstraint(timestampConclusion, timestamp)) {
				continue;
			}
			if (!checkMessageImprintDataIntactConstraint(timestampConclusion, timestamp)) {
				continue;
			}
			if (contentTimestamp) {

				checkTimestampValidationProcessConstraint();
			} else {

				found = checkTimestampValidationProcessConstraint(rightTimestamps, found, productionTime);
			}
		}

		// -1 means that there is no timestamps within the signature
		//  0 means that there is no valid timestamps
		//  1 means that there is at least one valid timestamp
		final int validTimestampCount = noContentTimestampCount == 0 ? -1 : (found ? 1 : 0);
		if (!checkTimestampsValidationProcessConstraint(signatureConclusion, validTimestampCount)) {
			return signatureConclusion;
		}

		/**
		 * 5) Comparing times:
		 */

		/**
		 * NOTE 2:
		 */
		if (Indication.INDETERMINATE.equals(bvpIndication) && SubIndication.REVOKED_NO_POE.equals(bvpSubIndication)) {

			if (!checkRevocationTimeConstraint(signatureConclusion)) {
				return signatureConclusion;
			}
		}

		/**
		 * NOTE 3:
		 */
		if (Indication.INDETERMINATE.equals(bvpIndication) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bvpSubIndication)) {

			if (!checkBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint(signatureConclusion)) {
				return signatureConclusion;
			}
			if (!checkSigningCertificateValidityAtBestSignatureTimeConstraint(signatureConclusion)) {
				return signatureConclusion;
			}
		}

		/**
		 * NOTE 4:
		 */
		if (Indication.INDETERMINATE.equals(bvpIndication) && SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bvpSubIndication)) {

			if (!checkAlgorithmReliableAtBestSignatureTimeConstraint(signatureConclusion)) {
				return signatureConclusion;
			}
		}

		if (!checkTimestampCoherenceConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkSigningTimeProperty(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkTimestampDelay(signatureConclusion)) {
			return signatureConclusion;
		}

		// This validation process returns VALID
		signatureConclusion.setIndication(Indication.VALID);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		signatureConclusion.addInfo(MessageTag.EMPTY).setAttribute(AttributeValue.BEST_SIGNATURE_TIME, formatedBestSignatureTime);

		return signatureConclusion;
	}

	private boolean isContentTimestamp(TimestampType timestampType) {
		return (TimestampType.ALL_DATA_OBJECTS_TIMESTAMP == timestampType) || (TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP == timestampType) || (TimestampType.CONTENT_TIMESTAMP == timestampType);
	}

	private Date getLatestTimestampProductionDate(final List<XmlDom> timestamps, final TimestampType selectedTimestampType) {


		Date latestProductionTime = null;
		for (final XmlDom timestamp : timestamps) {

			final String timestampType = timestamp.getValue("./@Type");
			if (!selectedTimestampType.name().equals(timestampType)) {
				continue;
			}
			final Date productionTime = timestamp.getTimeValue("./ProductionTime/text()");
			if ((latestProductionTime == null) || latestProductionTime.before(productionTime)) {

				latestProductionTime = productionTime;
			}
		}
		return latestProductionTime;
	}

	/**
	 * b) Time-stamp token validation: For each time-stamp token remaining in the set of signature time-stamp
	 * tokens, the SVA shall perform the time-stamp validation process (see clause 7):<br/>
	 *
	 * 􀀀 If VALID is returned and if the returned generation time is before best-signature-time, set
	 * best-signature-time to this date and try the next token.<br/>
	 *
	 * 􀀀 In all remaining cases, remove the time-stamp token from the set of signature time-stamp tokens and try
	 * the next token.<br/>
	 *
	 * @param rightTimestamps the {@code List} containing the id of valid valid timestamps
	 * @param found           indicates if there is at least one valid timestamp
	 * @param productionTime  the production {@code Date} of the current timestamp
	 * @return
	 */
	private boolean checkTimestampValidationProcessConstraint(final List<String> rightTimestamps, final boolean found, final Date productionTime) {

		final XmlDom tspvData = timestampValidationData.getElement("/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']", signatureId, timestampId);
		final XmlDom tsvpConclusion = tspvData.getElement("./BasicBuildingBlocks/Conclusion");
		final String tsvpIndication = tsvpConclusion.getValue("./Indication/text()");
		final String tsvpSubIndication = tsvpConclusion.getValue("./SubIndication/text()");

		final XmlNode constraintNode = addConstraint(timestampXmlNode, MessageTag.ADEST_ITVPC);

		boolean valid = Indication.VALID.equals(tsvpIndication);
		boolean cryptoConstraintsFailureNoPoe = SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(tsvpSubIndication);
		boolean revokedNoPoe = SubIndication.REVOKED_NO_POE.equals(tsvpSubIndication);
		boolean outOfBoundsNoPoe = SubIndication.OUT_OF_BOUNDS_NO_POE.equals(tsvpSubIndication);

		if (valid || cryptoConstraintsFailureNoPoe || revokedNoPoe || outOfBoundsNoPoe) {

			if (productionTime.before(bestSignatureTime)) {

				constraintNode.addChild(NodeName.STATUS, NodeValue.OK);

				bestSignatureTime = productionTime;
				constraintNode.addChild(NodeName.INFO, MessageTag.ADEST_ITVPC_INFO_1);
				rightTimestamps.add(timestampId);
				return true;
			} else {

				constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
				constraintNode.addChild(NodeName.WARNING, MessageTag.ADEST_ITVPC_ANS_1);
			}
			return found;
		}
		constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
		constraintNode.addChild(NodeName.ERROR, MessageTag.ADEST_ITVPC_ANS_2);
		// TODO: (Bob: 2014 Mar 15) the information from the timestamp validation process should be copied.
		return found;
	}

	/**
	 * Same as previous method ({@code #checkTimestampValidationProcessConstraint}), but does not add the timestamp to the list of right timestamps, and does not return any result
	 * -> Only performs the functional validation of the timestamp
	 *
	 * @return
	 */
	private void checkTimestampValidationProcessConstraint() {

		final XmlDom tspvData = timestampValidationData.getElement("/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']", signatureId, timestampId);
		final XmlDom tsvpConclusion = tspvData.getElement("./BasicBuildingBlocks/Conclusion");
		final String tsvpIndication = tsvpConclusion.getValue("./Indication/text()");

		final XmlNode constraintNode = addConstraint(timestampXmlNode, MessageTag.ADEST_ITVPC);

		if (Indication.VALID.equals(tsvpIndication)) {
			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);
			constraintNode.addChild(NodeName.INFO, MessageTag.ADEST_ITVPC_INFO_1);
		} else {
			constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
			constraintNode.addChild(NodeName.ERROR, MessageTag.ADEST_ITVPC_ANS_2);
		}
	}

	private Date getEarliestTimestampProductionTime(final List<XmlDom> timestamps, final TimestampType selectedTimestampType) {

		Date earliestProductionTime = null;
		for (final XmlDom timestamp : timestamps) {

			final String timestampType = timestamp.getValue("./@Type");
			if (!selectedTimestampType.name().equals(timestampType)) {
				continue;
			}
			final Date productionTime = timestamp.getTimeValue("./ProductionTime/text()");
			if ((earliestProductionTime == null) || earliestProductionTime.after(productionTime)) {

				earliestProductionTime = productionTime;
			}
		}
		return earliestProductionTime;
	}

	/**
	 * @param parent
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final XmlNode parent, final MessageTag messageTag) {

		XmlNode constraintNode = parent.addChild(NodeName.CONSTRAINT);
		constraintNode.addChild(NodeName.NAME, messageTag.getMessage()).setAttribute(AttributeName.NAME_ID, messageTag.name());
		return constraintNode;
	}

	/**
	 * Check of: the result of the basic validation process
	 *
	 * NOTE 2: We continue the process in the case INDETERMINATE/REVOKED_NO_POE, because a proof that the signing
	 * occurred before the revocation date may help to go from INDETERMINATE to VALID (step 5-a).
	 *
	 * NOTE 3: We continue the process in the case INDETERMINATE/OUT_OF_BOUNDS_NO_POE, because a proof that the
	 * signing occurred before the issuance date (notBefore) of the signer's certificate may help to go from
	 * INDETERMINATE to INVALID (step 5-b).
	 *
	 * NOTE 4: We continue the process in the case INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, because a proof
	 * that the signing occurred before the time one of the algorithms used was no longer considered secure may help
	 * to go from INDETERMINATE to VALID (step 5-c).
	 *
	 * AT: Problem of the revocation of the certificate after signing time --> Following the Austrian's laws the signature is still valid because the timestamps are not
	 * mandatory, what is an aberration. To obtain the validity of such a signature the rule which checks the revocation data should be set as WARN. Then here VALID
	 * indication is obtained.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkBasicValidationProcessConclusionConstraint(final Conclusion conclusion) {

		final BasicValidationProcessValidConstraint constraint = constraintData.getBasicValidationProcessConclusionConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.ADEST_ROBVPIIC);
		boolean validBasicValidationProcess = Indication.VALID.equals(bvpIndication) || (Indication.INDETERMINATE.equals(bvpIndication) && (RuleUtils
				.in(bvpSubIndication, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, SubIndication.OUT_OF_BOUNDS_NO_POE, SubIndication.REVOKED_NO_POE)));
		constraint.setValue(validBasicValidationProcess);
		constraint.setBasicValidationProcessConclusionNode(bvpConclusion);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: is the timestamp message imprint data found
	 *
	 * 4) Signature time-stamp validation: Perform the following steps:
	 *
	 * a) Message imprint verification: For each time-stamp token in the set of signature time-stamp tokens, do the
	 * message imprint verification as specified in clauses 8.4.1 or 8.4.2 depending on the type of the signature.
	 * If the verification fails, remove the token from the set.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @param timestamp
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkMessageImprintDataFoundConstraint(final Conclusion conclusion, final XmlDom timestamp) {

		final Constraint constraint = constraintData.getMessageImprintDataFoundConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(timestampXmlNode, MessageTag.ADEST_IMIDF);
		final boolean messageImprintDataIntact = timestamp.getBoolValue(ValidationXPathQueryHolder.XP_MESSAGE_IMPRINT_DATA_FOUND);
		constraint.setValue(messageImprintDataIntact);
		constraint.setIndications(MessageTag.ADEST_IMIDF_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: is the timestamp message imprint data intact
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @param timestamp
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkMessageImprintDataIntactConstraint(final Conclusion conclusion, final XmlDom timestamp) {

		final Constraint constraint = constraintData.getMessageImprintDataIntactConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(timestampXmlNode, MessageTag.ADEST_IMIVC);
		final boolean messageImprintDataIntact = timestamp.getBoolValue(ValidationXPathQueryHolder.XP_MESSAGE_IMPRINT_DATA_INTACT);
		constraint.setValue(messageImprintDataIntact);
		constraint.setIndications(MessageTag.ADEST_IMIVC_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: Is the result of the timestamps validation process conclusive?
	 *
	 * @param conclusion          the conclusion to use to add the result of the check.
	 * @param validTimestampCount
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkTimestampsValidationProcessConstraint(final Conclusion conclusion, final int validTimestampCount) {

		final TimestampValidationProcessValidConstraint constraint = constraintData.getTimestampValidationProcessConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.ADEST_ROTVPIIC);
		constraint.setValidTimestampCount(validTimestampCount);
		constraint.setIndications(Indication.INDETERMINATE, null, MessageTag.ADEST_ROTVPIIC_ANS);
		constraint.setSubIndication1(SubIndication.NO_VALID_TIMESTAMP);
		constraint.setSubIndication2(SubIndication.NO_TIMESTAMP);
		final String formattedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(AttributeValue.BEST_SIGNATURE_TIME, formattedBestSignatureTime);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: Is revocation time posterior to best-signature-time?
	 *
	 * a) If step 2 returned INDETERMINATE/REVOKED_NO_POE: If the returned revocation time is posterior to
	 * best-signature-time, perform step 5d. Otherwise, terminate with INDETERMINATE/REVOKED_NO_POE. In addition to
	 * the data items returned in steps 1 and 2, the SVA should notify the DA with the reason of the failure.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkRevocationTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getRevocationTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.ADEST_IRTPTBST);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.REVOKED_NO_POE, MessageTag.ADEST_IRTPTBST_ANS);
		final Date revocationDate = bvpConclusion.getTimeValue("./Error/@RevocationTime");
		final boolean before = bestSignatureTime.before(revocationDate);
		constraint.setValue(before);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(AttributeValue.BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		// TODO: (Bob: 2014 Mar 16)
		//        final XmlDom errorXmlDom = bvpConclusion.getElement("./Error");
		//        conclusionNode.addChild(errorXmlDom);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: best-signature-time against the signing certificate issuance date.
	 *
	 * b) If step 2 returned INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the issuance date
	 * of the signer's certificate, terminate with INVALID/NOT_YET_VALID.
	 *
	 * NOTE 5: In the algorithm above, the signature-time-stamp protects the signature against the revocation of
	 * the signer's certificate (step 5-a) but not against expiration. The latter case requires validating the
	 * signer's certificate in the past (see clause 9).
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.TSV_IBSTAIDOSC);
		constraint.setIndications(Indication.INVALID, SubIndication.NOT_YET_VALID, MessageTag.TSV_IBSTAIDOSC_ANS);
		final String formatedNotBefore = bvpConclusion.getValue("./Error/@NotBefore");
		final Date notBeforeTime = DSSUtils.parseDate(formatedNotBefore);
		final boolean notBefore = !bestSignatureTime.before(notBeforeTime);
		constraint.setValue(notBefore);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(AttributeValue.BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		constraint.setAttribute(AttributeValue.NOT_BEFORE, formatedNotBefore);
		// TODO: (Bob: 2014 Mar 16)
		//        final XmlDom errorXmlDom = bvpConclusion.getElement("./Error");
		//        conclusionNode.addChild(errorXmlDom);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: best-signature-time against the signing certificate issuance date.
	 *
	 * b) If step 2 returned INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If best-signature-time is not before the issuance date
	 * of the signer's certificate terminate with INDETERMINATE/OUT_OF_BOUNDS_NO_POE. In addition to the data items returned
	 * in steps 1 and 2, the SVA should notify the DA with the reason of the failure.
	 *
	 * NOTE 5: In the algorithm above, the signature-time-stamp protects the signature against the revocation of
	 * the signer's certificate (step 5-a) but not against expiration. The latter case requires validating the
	 * signer's certificate in the past (see clause 9).
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSigningCertificateValidityAtBestSignatureTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSigningCertificateValidityAtBestSignatureTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.TSV_ISCNVABST);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.OUT_OF_BOUNDS_NO_POE, MessageTag.TSV_ISCNVABST_ANS);
		// false is always returned: this corresponds to: Otherwise, terminate with INDETERMINATE/OUT_OF_BOUNDS_NO_POE.
		constraint.setValue(false);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(AttributeValue.BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		// TODO: (Bob: 2014 Mar 16)
		//        final XmlDom errorXmlDom = bvpConclusion.getElement("./Error");
		//        conclusionNode.addChild(errorXmlDom);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: best-signature-time against the signing certificate issuance date.
	 *
	 * c) If step 2 returned INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by this
	 * failure is the signature value or a signed attribute, check, if the algorithm(s) concerned were still
	 * considered reliable at best-signature-time, continue with step d. Otherwise, terminate with
	 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkAlgorithmReliableAtBestSignatureTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getAlgorithmReliableAtBestSignatureTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.TSV_WACRABST);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, MessageTag.TSV_WACRABST_ANS);

		boolean ok = false;
		final XmlDom error = bvpConclusion.getElement("./Error");
		if (error != null) {

			final String algorithmExpirationDateString = error.getAttribute("AlgorithmExpirationDate");
			if (StringUtils.isNotBlank(algorithmExpirationDateString)) {

				final Date algorithmExpirationDate = DSSUtils.parseDate(DSSUtils.DEFAULT_DATE_FORMAT, algorithmExpirationDateString);
				if (!algorithmExpirationDate.before(bestSignatureTime)) {

					ok = true;
				}
			}
		}
		constraint.setValue(ok);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(AttributeValue.BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		// TODO: (Bob: 2014 Mar 16)
		//        final XmlDom errorXmlDom = bvpConclusion.getElement("./Error");
		//        conclusionNode.addChild(errorXmlDom);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * d) For each time-stamp token remaining in the set of signature time-stamp tokens, check the coherence in the
	 * values of the times indicated in the time-stamp tokens. They shall be posterior to the times indicated in any
	 * time-stamp token computed on the signed data (i.e. any content-time-stamp signed attributes in CAdES or any
	 * AllDataObjectsTimeStamp or IndividualDataObjectsTimeStamp signed present properties in XAdES). The SVA shall
	 * apply the rules specified in RFC 3161 [11], clause 2.4.2 regarding the order of time-stamp tokens generated by
	 * the same or different TSAs given the accuracy and ordering fields' values of the TSTInfo field, unless stated
	 * differently by the Signature Constraints. If all the checks end successfully, go to the next step. Otherwise
	 * return INVALID/TIMESTAMP_ORDER_FAILURE.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkTimestampCoherenceConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getTimestampCoherenceConstraint();
		if (constraint == null) {
			return true;
		}

		final List<XmlDom> timestamps = signatureXmlDom.getElements("./Timestamps/Timestamp");

		for (int index = timestamps.size() - 1; index >= 0; index--) {

			final XmlDom timestamp = timestamps.get(index);
			String timestampId = timestamp.getValue("./@Id");
			final XmlDom tspvData = timestampValidationData.getElement("/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']", signatureId, timestampId);
			final XmlDom tsvpConclusion = tspvData.getElement("./BasicBuildingBlocks/Conclusion");
			final String tsvpIndication = tsvpConclusion.getValue("./Indication/text()");
			if (!Indication.VALID.equals(tsvpIndication)) {

				timestamps.remove(index);
			}
		}
		Date latestContent = getLatestTimestampProductionDate(timestamps, TimestampType.CONTENT_TIMESTAMP);
		Date latestContent_ = getLatestTimestampProductionDate(timestamps, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		latestContent = getLatestDate(latestContent, latestContent_);
		latestContent_ = getLatestTimestampProductionDate(timestamps, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		latestContent = getLatestDate(latestContent, latestContent_);

		final Date earliestSignature = getEarliestTimestampProductionTime(timestamps, TimestampType.SIGNATURE_TIMESTAMP);
		final Date latestSignature = getLatestTimestampProductionDate(timestamps, TimestampType.SIGNATURE_TIMESTAMP);

		Date earliestValidationData = getEarliestTimestampProductionTime(timestamps, TimestampType.VALIDATION_DATA_TIMESTAMP);
		final Date earliestValidationData_ = getEarliestTimestampProductionTime(timestamps, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		earliestValidationData = getEarliestDate(earliestValidationData, earliestValidationData_);

		final Date earliestArchive = getEarliestTimestampProductionTime(timestamps, TimestampType.ARCHIVE_TIMESTAMP);

		Date latestValidationData = getLatestTimestampProductionDate(timestamps, TimestampType.VALIDATION_DATA_TIMESTAMP);
		final Date latestValidationData_ = getLatestTimestampProductionDate(timestamps, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		latestValidationData = getLatestDate(latestValidationData, latestValidationData_);

		if ((latestContent == null) && (earliestSignature == null) && (earliestValidationData == null) && (earliestArchive == null)) {
			return true;
		}
		boolean ok = true;

		if ((earliestSignature == null) && ((earliestValidationData != null) || (earliestArchive != null))) {
			ok = false;
		}

		// Check content-timestamp against-signature timestamp
		if ((latestContent != null) && (earliestSignature != null)) {
			ok = ok && latestContent.before(earliestSignature);
		}

		// Check signature-timestamp against validation-data and validation-data-refs-only timestamp
		if ((latestSignature != null) && (earliestValidationData != null)) {
			ok = ok && latestSignature.before(earliestValidationData);
		}

		// Check archive-timestamp
		if ((latestSignature != null) && (earliestArchive != null)) {
			ok = ok && earliestArchive.after(latestSignature);
		}

		if ((latestValidationData != null) && (earliestArchive != null)) {
			ok = ok && earliestArchive.after(latestValidationData);
		}

		constraint.create(signatureXmlNode, MessageTag.TSV_ASTPTCT);
		constraint.setIndications(Indication.INVALID, SubIndication.TIMESTAMP_ORDER_FAILURE, MessageTag.TSV_ASTPTCT_ANS);

		constraint.setValue(ok);

		final String formattedLatestContentTimestampProductionDate = DSSUtils.formatDate(latestContent);
		final String formattedEarliestSignatureTimestampProductionDate = DSSUtils.formatDate(earliestSignature);
		constraint.setAttribute(AttributeValue.LATEST_CONTENT_TIMESTAMP_PRODUCTION_TIME, formattedLatestContentTimestampProductionDate);
		constraint.setAttribute(AttributeValue.EARLIEST_SIGNATURE_TIMESTAMP_PRODUCTION_TIME, formattedEarliestSignatureTimestampProductionDate);

		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	private static Date getLatestDate(Date firstDate, final Date secondDate) {

		if ((firstDate != null) && (secondDate != null)) {
			if (firstDate.before(secondDate)) {
				firstDate = secondDate;
			}
		} else if (secondDate != null) {
			firstDate = secondDate;
		}
		return firstDate;
	}

	private static Date getEarliestDate(Date firstDate, final Date secondDate) {

		if ((firstDate != null) && (secondDate != null)) {
			if (firstDate.after(secondDate)) {
				firstDate = secondDate;
			}
		} else if (secondDate != null) {
			firstDate = secondDate;
		}
		return firstDate;
	}

	/**
	 * Check of: Time-stamp delay.
	 *
	 * 6) Handling Time-stamp delay: If the validation constraints specify a time-stamp delay, do the following:
	 *
	 * a) If no signing-time property/attribute is present, fail with INDETERMINATE and an explanation that the
	 * validation failed due to the absence of claimed signing time.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSigningTimeProperty(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getTimestampDelaySigningTimePropertyConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.BBB_SAV_ISQPSTP);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.CLAIMED_SIGNING_TIME_ABSENT, MessageTag.ADEST_VFDTAOCST_ANS);
		final String signingTime = signatureXmlDom.getValue("./DateTime/text()");
		constraint.setValue(StringUtils.isNotBlank(signingTime));
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: Time-stamp delay.
	 *
	 * b) If a signing-time property/attribute is present, check that the claimed time in the attribute plus the
	 * timestamp delay is after the best-signature-time. If the check is successful, go to the next step.
	 * Otherwise, fail with INVALID/SIG_CONSTRAINTS_FAILURE and an explanation that the validation failed due to
	 * the time-stamp delay constraint.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkTimestampDelay(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getTimestampDelaySigningTimePropertyConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, MessageTag.ADEST_ISTPTDABST);
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.ADEST_ISTPTDABST_ANS);
		final Long timestampDelay = constraintData.getTimestampDelayTime();
		final String signingTime = signatureXmlDom.getValue("./DateTime/text()");
		final Date date = DSSUtils.quietlyParseDate(signingTime);
		constraint.setValue((date.getTime() + timestampDelay) > bestSignatureTime.getTime());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}
}
