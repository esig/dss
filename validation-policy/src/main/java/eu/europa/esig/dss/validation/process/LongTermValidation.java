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

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ltv.PastSignatureValidation;
import eu.europa.esig.dss.validation.process.ltv.PastSignatureValidationConclusion;
import eu.europa.esig.dss.validation.process.subprocess.EtsiPOEExtraction;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * 9.3 Long Term Validation Process<br>
 *
 * 9.3.1 Description<br>
 *
 * An AdES-A (Archival Electronic Signature) is built on an XL signature (EXtended Long Electronic Signature). Several
 * unsigned attributes may be present in such signatures:<br>
 *
 * • Time-stamp(s) on the signature value (AdES-T).<br>
 * • Attributes with references of validation data (AdES-C).<br>
 * • Time-stamp(s) on the references of validation data (AdES-XT2).<br>
 * • Time-stamp(s) on the references of validation data, the signature value and the signature time stamp (AdES-XT1).<br>
 * • Attributes with the values of validation data (AdES-XL).<br>
 * • Archive time-stamp(s) on the whole signature except the last archive time-stamp (AdES-A).<br>
 *
 * The process described in this clause is able to validate any of the forms above but also any basic form (namely BES
 * and EPES).<br>
 *
 * The process handles the AdES signature as a succession of layers of signatures. Starting from the most external layer
 * (e.g. the last archive-time-stamp) to the most inner layer (the signature value to validate), the process performs
 * the basic signature validation algorithm (see clause 8 for the signature itself and clause 7 for the time-stamps). If
 * the basic validation outputs INDETERMINATE/REVOKED_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE or
 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, we perform the past certificate validation which will output a
 * control-time in the past. The layer is accepted as VALID, provided we have a proof of existence before this
 * control-time.<br>
 *
 * The process does not necessarily fail when an intermediate time-stamp gives the status INVALID or INDETERMINATE
 * unless some validation constraints force the process to do so. If the validity of the signature can be ascertained
 * despite some time-stamps which were ignored due to INVALID (or INDETERLINATE) status, the SVA shall report this
 * information to the DA. What the DA does with this information is out of the scope of the present document.
 *
 *
 */
public class LongTermValidation {

	private static final Logger LOG = LoggerFactory.getLogger(LongTermValidation.class);

	ProcessParameters params;

	// Primary inputs
	/**
	 * See {@link eu.europa.esig.dss.validation.policy.ProcessParameters#getDiagnosticData()}
	 *
	 * @return
	 */
	private XmlDom diagnosticData;

	private XmlDom timestampValidationData; // Basic Building Blocks for timestamps

	private XmlDom adestValidationData;

	// returned data
	private XmlNode signatureNode;
	private XmlNode conclusionNode;

	// This object represents the set of POEs.
	private EtsiPOEExtraction poe;

	private void prepareParameters(final XmlNode mainNode) {

		this.diagnosticData = params.getDiagnosticData();
		isInitialised(mainNode);
	}

	private void isInitialised(final XmlNode mainNode) {

		if (diagnosticData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (params.getValidationPolicy() == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (adestValidationData == null) {

			/**
			 * The execution of the Basic Validation process which creates the basic validation data.<br>
			 */
			final AdESTValidation adestValidation = new AdESTValidation();
			adestValidationData = adestValidation.run(mainNode, params);

			// Basic Building Blocks for timestamps
			timestampValidationData = params.getTsData();
		}
		if (poe == null) {

			poe = new EtsiPOEExtraction();
			params.setPOE(poe);
		}
	}

	/**
	 * This method lunches the long term validation process.
	 *
	 * 9.3.2 Input<br>
	 * Signature ..................... Mandatory<br>
	 * Signed data object (s) ........ Optional<br>
	 * Trusted-status Service Lists .. Optional<br>
	 * Signature Validation Policies . Optional<br>
	 * Local configuration ........... Optional<br>
	 * A set of POEs ................. Optional<br>
	 * Signer's Certificate .......... Optional<br>
	 *
	 * 9.3.3 Output<br>
	 * The main output of this signature validation process is a status indicating the validity of the signature. This
	 * status may be accompanied by additional information (see clause 4).<br>
	 *
	 * 9.3.4 Processing<br>
	 * The following steps shall be performed:
	 *
	 * @param params
	 * @return
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

		this.params = params;
		prepareParameters(mainNode);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		XmlNode longTermValidationData = mainNode.addChild(NodeName.LONG_TERM_VALIDATION_DATA);

		final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");

		for (final XmlDom signature : signatures) {

			final String signatureId = signature.getValue("./@Id");
			final String type = signature.getValue("./@Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {

				params.setCurrentValidationPolicy(params.getCountersignatureValidationPolicy());
			} else {

				params.setCurrentValidationPolicy(params.getValidationPolicy());
			}
			final XmlDom signatureTimestampValidationData = timestampValidationData.getElement("./Signature[@Id='%s']", signatureId);
			final XmlDom adestSignatureValidationData = adestValidationData.getElement("/AdESTValidationData/Signature[@Id='%s']", signatureId);

			signatureNode = longTermValidationData.addChild(NodeName.SIGNATURE);
			signatureNode.setAttribute(AttributeName.ID, signatureId);

			conclusionNode = new XmlNode(NodeName.CONCLUSION);
			try {

				final boolean valid = process(params, signature, signatureTimestampValidationData, adestSignatureValidationData);
				if (valid) {

					conclusionNode.addFirstChild(NodeName.INDICATION, Indication.VALID);
				}
			} catch (Exception e) {

				LOG.warn("Unexpected exception: " + e.getMessage(), e);
			}
			conclusionNode.setParent(signatureNode);
		}
		final XmlDom ltvDom = longTermValidationData.toXmlDom();
		params.setLtvData(ltvDom);
		return ltvDom;
	}

	/**
	 * 9.3.4 Processing<br>
	 *
	 * The following steps shall be performed:<br>
	 *
	 * @param params
	 * @param signature
	 * @param signatureTimestampValidationData
	 * @param adestSignatureValidationData
	 * @return
	 */
	private boolean process(ProcessParameters params, XmlDom signature, XmlDom signatureTimestampValidationData, XmlDom adestSignatureValidationData) {

		/**
		 * 1) POE initialisation: Add a POE for each object in the signature at the current time to the set of POEs.<br>
		 *
		 * NOTE 1: The set of POE in the input may have been initialised from external sources (e.g. provided from an
		 * external archiving system). These POEs will be used without additional processing.<br>
		 */
		// This means that the framework needs to extend the signature (add a LTV timestamp).
		// --> This is not done in the 102853 implementation. The DSS user can extend the signature by adding his own
		// code.

		final List<XmlDom> certificates = params.getCertPool().getElements("./Certificate");
		//!! poe.initialisePOE(signature, certificates, params.getCurrentTime());

		/**
		 * 2) Basic signature validation: Perform the validation process for AdES-T signatures (see clause 8) with all the
		 * inputs, including the processing of any signed attributes/properties as specified.<br>
		 */

		// --> This is done in the prepareParameters(ProcessParameters params) method.

		final XmlDom adestSignatureConclusion = adestSignatureValidationData.getElement("./Conclusion");
		final String adestSignatureIndication = adestSignatureConclusion.getValue("./Indication/text()");
		final String adestSignatureSubIndication = adestSignatureConclusion.getValue("./SubIndication/text()");

		/**
		 * - If the validation outputs VALID<br>
		 * - - If there is no validation constraint mandating the validation of the LTV attributes/properties, go to step
		 * 9.<br>
		 * - - Otherwise, go to step 3.<br>
		 * TODO: 20130702 by bielecro: To notify ETSI --> There is no step 9.
		 *
		 */

		XmlNode constraintNode = addConstraint(signatureNode, MessageTag.PSV_IATVC);

		if (Indication.VALID.equals(adestSignatureIndication)) {

			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);
			final List<XmlDom> adestInfo = adestSignatureConclusion.getElements("./Info");
			constraintNode.addChildren(adestInfo);
			conclusionNode.addChildren(adestInfo);
			return true;
		}

		/**
		 * - If the validation outputs one of the following:<br>
		 * -- INDETERMINATE/REVOKED_NO_POE,<br>
		 * -- INDETERMINATE/REVOKED_CA_NO_POE,<br>
		 * -- INDETERMINATE/OUT_OF_BOUNDS_NO_POE or<br>
		 * -- INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,<br>
		 * go to the next step.<br>
		 *
		 * - In all other cases, fail with returned code and information.<br>
		 *
		 * NOTE 2: We go to the LTV part of the validation process in the cases INDETERMINATE/REVOKED_NO_POE,
		 * INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE and INDETERMINATE/
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE because additional proof of existences may help to go from INDETERMINATE to a
		 * determined status.<br>
		 *
		 * NOTE 3: Performing the LTV part of the algorithm even when the basic validation gives VALID may be useful in
		 * the case the SVA is controlled by an archiving service. In such cases, it may be necessary to ensure that any
		 * LTV attribute/property present in the signature is actually valid before making a decision about the archival
		 * of the signature.<br>
		 */
		final boolean finalStatus = Indication.INDETERMINATE.equals(adestSignatureIndication) && (RuleUtils
				.in(adestSignatureSubIndication, SubIndication.REVOKED_NO_POE, SubIndication.REVOKED_CA_NO_POE, SubIndication.OUT_OF_BOUNDS_NO_POE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE));
		if (!finalStatus) {

			conclusionNode.addChildrenOf(adestSignatureConclusion);
			constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
			constraintNode.addChild(NodeName.INFO, adestSignatureIndication).setAttribute(AttributeName.FIELD, NodeName.INDICATION);
			constraintNode.addChild(NodeName.INFO, adestSignatureSubIndication).setAttribute(AttributeName.FIELD, NodeName.SUB_INDICATION);
			return false;
		}
		constraintNode.addChild(NodeName.STATUS, NodeValue.OK);
		constraintNode.addChild(NodeName.INFO, adestSignatureIndication).setAttribute(AttributeName.FIELD, NodeName.INDICATION);
		constraintNode.addChild(NodeName.INFO, adestSignatureSubIndication).setAttribute(AttributeName.FIELD, NodeName.SUB_INDICATION);

		/**
		 * 3) If there is at least one long-term-validation attribute with a poeValue, process them, starting from the
		 * last (the newest) one as follows: Perform the time-stamp validation process (see clause 7) for the time-stamp
		 * in the poeValue:<br>
		 * a) If VALID is returned and the cryptographic hash function used in the time-stamp
		 * (MessageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp: Perform the POE
		 * extraction process with the signature, the long-term-validation attribute, the set of POEs and the
		 * cryptographic constraints as inputs. Add the returned POEs to the set of POEs.<br>
		 * b) Otherwise, perform past signature validation process with the following inputs: the time-stamp in the
		 * poeValue, the status/sub-indication returned in step 3, the TSA's certificate, the X.509 validation parameters,
		 * certificate meta-data, chain constraints, cryptographic constraints and the set of POEs. If it returns VALID
		 * and the cryptographic hash function used in the time-stamp is considered reliable at the generation time of the
		 * time-stamp, perform the POE extraction process and add the returned POEs to the set of POEs. In all other
		 * cases:<br>
		 * 􀀀 If no specific constraints mandating the validity of the attribute are specified in the validation
		 * constraints, ignore the attribute and consider the next long-term-validation attribute.<br>
		 * 􀀀 Otherwise, fail with the returned indication/sub-indication and associated explanations<br>
		 */

		// TODO 20130702 by bielecro: This must be implemented with the new CAdES Baseline Profile.
		// This is the part of the new CAdES specification:
		// http://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.01.01_60/ts_101733v020101p.pdf

		/**
		 * 4) If there is at least one archive-time-stamp attribute, process them, starting from the last (the newest)
		 * one, as follows: perform the time-stamp validation process (see clause 7):
		 */
		final XmlNode archiveTimestampsNode = signatureNode.addChild("ArchiveTimestamps");
		final List<XmlDom> archiveTimestamps = signature.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.ARCHIVE_TIMESTAMP);
		if (archiveTimestamps.size() > 0) {

			dealWithTimestamp(archiveTimestampsNode, signatureTimestampValidationData, archiveTimestamps);
		}

		/**
		 * 5) If there is at least one time-stamp attribute on the references, process them, starting from the last one
		 * (the newest), as follows: perform the time-stamp validation process (see clause 7):<br>
		 */

		final XmlNode refsOnlyTimestampsNode = signatureNode.addChild("RefsOnlyTimestamps");
		final List<XmlDom> refsOnlyTimestamps = signature.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		if (refsOnlyTimestamps.size() > 0) {

			dealWithTimestamp(refsOnlyTimestampsNode, signatureTimestampValidationData, refsOnlyTimestamps);
		}

		/**
		 * 6) If there is at least one time-stamp attribute on the references and the signature value, process them,
		 * starting from the last one, as follows: perform the time-stamp validation process (see clause 7):<br>
		 */

		final XmlNode sigAndRefsTimestampsNode = signatureNode.addChild("SigAndRefsTimestamps");
		final List<XmlDom> sigAndRefsTimestamps = signature.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.VALIDATION_DATA_TIMESTAMP);
		if (sigAndRefsTimestamps.size() > 0) {

			dealWithTimestamp(sigAndRefsTimestampsNode, signatureTimestampValidationData, sigAndRefsTimestamps);
		}
		/**
		 * 7) If there is at least one signature-time-stamp attribute, process them, in the order of their appearance
		 * starting from the last one, as follows: Perform the time-stamp validation process (see clause 7)<br>
		 */

		final XmlNode timestampsNode = signatureNode.addChild("Timestamps");
		final List<XmlDom> timestamps = signature.getElements("./Timestamps/Timestamp[@Type='%s']", TimestampType.SIGNATURE_TIMESTAMP);
		if (timestamps.size() > 0) {

			dealWithTimestamp(timestampsNode, signatureTimestampValidationData, timestamps);
		}
		/**
		 * 8) Past signature validation: perform the past signature validation process with the following inputs: the
		 * signature, the status indication/sub-indication returned in step 2, the signer's certificate, the x.509
		 * validation parameters, certificate meta-data, chain constraints, cryptographic constraints and the set of POEs.
		 */

		final PastSignatureValidation pastSignatureValidation = new PastSignatureValidation();

		final PastSignatureValidationConclusion psvConclusion = pastSignatureValidation.run(params, signature, adestSignatureConclusion, NodeName.MAIN_SIGNATURE);

		signatureNode.addChild(psvConclusion.getValidationData());
		/**
		 * If it returns VALID go to the next step. Otherwise, abort with the returned indication/sub-indication and
		 * associated explanations.<br>
		 */

		constraintNode = addConstraint(signatureNode, MessageTag.PSV_IPSVC);

		if (!Indication.VALID.equals(psvConclusion.getIndication())) {

			constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
			constraintNode.addChild(NodeName.INFO, psvConclusion.getIndication()).setAttribute(AttributeName.FIELD, NodeName.INDICATION);
			constraintNode.addChild(NodeName.INFO, psvConclusion.getSubIndication()).setAttribute(AttributeName.FIELD, NodeName.SUB_INDICATION);
			psvConclusion.infoToXmlNode(constraintNode);

			conclusionNode.addChild(NodeName.INDICATION, psvConclusion.getIndication());
			conclusionNode.addChild(NodeName.SUB_INDICATION, psvConclusion.getSubIndication());
			psvConclusion.infoToXmlNode(conclusionNode);
			return false;
		}
		constraintNode.addChild(NodeName.STATUS, NodeValue.OK);

		/**
		 * Data extraction: the SVA shall return the success indication VALID. In addition, the SVA should return
		 * additional information extracted from the signature and/or used by the intermediate steps. In particular, the
		 * SVA should return intermediate results such as the validation results of any time-stamp token or time-mark.
		 * What the DA does with this information is out of the scope of the present document.<br>
		 */
		return true;
	}

	/**
	 * @param processNode
	 * @param signatureTimestampValidationData
	 * @param timestamps
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private void dealWithTimestamp(final XmlNode processNode, final XmlDom signatureTimestampValidationData, final List<XmlDom> timestamps) throws DSSException {

		Collections.sort(timestamps, new TimestampComparator());
		for (final XmlDom timestamp : timestamps) {

			final String timestampId = timestamp.getValue("./@Id");
			try {

				/**
				 * FROM ADES-T (ETSI error ?!)
				 * 4) Signature time-stamp validation: Perform the following steps:
				 *
				 * a) Message imprint verification: For each time-stamp token in the set of signature time-stamp tokens, do the
				 * message imprint verification as specified in clauses 8.4.1 or 8.4.2 depending on the type of the signature.
				 * If the verification fails, remove the token from the set.
				 */

				XmlNode constraintNode = addConstraint(processNode, MessageTag.ADEST_IMIVC);
				// constraintNode.setAttribute("Id", timestampId);

				final boolean messageImprintDataIntact = timestamp.getBoolValue(ValidationXPathQueryHolder.XP_MESSAGE_IMPRINT_DATA_INTACT);
				if (!messageImprintDataIntact) {

					constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
					XmlNode xmlNode = conclusionNode.addChild(NodeName.INFO, MessageTag.ADEST_IMIVC_ANS.getMessage());
					xmlNode.setAttribute("Id", timestampId);
					continue;
				}
				constraintNode.addChild(NodeName.STATUS, NodeValue.OK);

				final XmlDom timestampConclusion = signatureTimestampValidationData.getElement("./Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion", timestampId);
				final String timestampIndication = timestampConclusion.getValue("./Indication/text()");

				/**
				 * a) If VALID is returned and the cryptographic hash function used in the time-stamp
				 * (MessageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp: Perform
				 * the POE extraction process with:<br>
				 * - the signature,<br>
				 * - the archive-time-stamp,<br>
				 * - the set of POEs and<br>
				 * - the cryptographic constraints as inputs.<br>
				 * Add the returned POEs to the set of POEs.
				 */
				if (Indication.VALID.equals(timestampIndication)) {

					processNode.addChild("POEExtraction", NodeValue.OK);
					extractPOEs(timestamp);
				} else {

					/**
					 * b) Otherwise, perform past signature validation process with the following inputs:<br>
					 * - the archive time-stamp,<br>
					 * - the status/sub-indication returned in step 4,<br>
					 * - the TSA's certificate,<br>
					 * - the X.509 validation parameters,<br>
					 * - certificate meta-data, <br>
					 * - chain constraints,<br>
					 * - cryptographic constraints and<br>
					 * - the set of POEs.
					 */

					final PastSignatureValidation psvp = new PastSignatureValidation();
					final PastSignatureValidationConclusion psvConclusion = psvp.run(params, timestamp, timestampConclusion, NodeName.TIMESTAMP);

					processNode.addChild(psvConclusion.getValidationData());

					/**
					 * If it returns VALID and the cryptographic hash function used in the time-stamp is considered reliable
					 * at the generation time of the time-stamp, perform the POE extraction process and add the returned POEs
					 * to the set of POEs.
					 */
					if (Indication.VALID.equals(psvConclusion.getIndication())) {

						final boolean couldExtract = extractPOEs(timestamp);
						if (couldExtract) {

							continue;
						}
					}
					/**
					 * In all other cases:<br>
					 * 􀀀 If no specific constraints mandating the validity of the attribute are specified in the validation
					 * constraints, ignore the attribute and consider the next archive-time-stamp attribute.<br>
					 */
					/**
					 * --> Concerning DSS there is no specific constraints.
					 */
					/**
					 * 􀀀 Otherwise, fail with the returned indication/sub-indication and associated explanations.<br>
					 *
					 * NOTE 4: If the signature is PAdES, document time-stamps replace archive-time-stamp attributes and the
					 * process "Extraction from a PDF document time-stamp" replaces the process
					 * "Extraction from an archive-time-stamp".<br>
					 */
				}
			} catch (Exception e) {

				throw new DSSException("Error for timestamp: id: " + timestampId, e);
			}
		}
	}

	/**
	 * @param timestamp
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private boolean extractPOEs(final XmlDom timestamp) throws DSSException {

		final String digestAlgorithm = RuleUtils.canonicalizeDigestAlgo(timestamp.getValue("./SignedDataDigestAlgo/text()"));
		final Date algorithmExpirationDate = params.getCurrentValidationPolicy().getAlgorithmExpirationDate(digestAlgorithm);
		final Date timestampProductionTime = timestamp.getTimeValue("./ProductionTime/text()");
		if ((algorithmExpirationDate == null) || timestampProductionTime.before(algorithmExpirationDate)) {

			poe.addPOE(timestamp, params.getCertPool());
			return true;
		}
		return false;
	}

	/**
	 * This method adds the constraint
	 *
	 * @param parentNode
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final XmlNode parentNode, final MessageTag messageTag) {

		final XmlNode constraintNode = parentNode.addChild(NodeName.CONSTRAINT);
		constraintNode.addChild(NodeName.NAME, messageTag.getMessage()).setAttribute(AttributeName.NAME_ID, messageTag.name());
		return constraintNode;
	}
}
