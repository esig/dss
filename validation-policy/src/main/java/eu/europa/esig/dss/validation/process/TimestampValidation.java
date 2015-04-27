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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.SignatureCryptographicConstraint;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.subprocess.CryptographicVerification;
import eu.europa.esig.dss.validation.process.subprocess.IdentificationOfTheSignersCertificate;
import eu.europa.esig.dss.validation.process.subprocess.X509CertificateValidation;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * 7 Validation Process for Time-Stamps<br>
 * <br>
 * 7.1 Description<br>
 * <br>
 * This clause describes a process for the validation of an RFC 3161 [11] time-stamp token. An RFC 3161 [11] time-stamp
 * token is basically a CAdES-BES signature. Hence, the validation process is built in the validation process of a
 * CAdES-BES signature.<br>
 *
 *
 */
public class TimestampValidation {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampValidation.class);

	private XmlDom diagnosticData;
	private ValidationPolicy constraintData;

	/**
	 * See {@link ProcessParameters#getCurrentTime()}
	 */
	private Date currentTime;

	private void prepareParameters(final ProcessParameters params) {

		this.diagnosticData = params.getDiagnosticData();
		this.currentTime = params.getCurrentTime();
		isInitialised(params);
	}

	private void isInitialised(final ProcessParameters params) {

		if (diagnosticData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (params.getValidationPolicy() == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (currentTime == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "currentTime"));
		}
	}

	/**
	 * 7.4 Processing<br>
	 *
	 * The following steps shall be performed:<br>
	 *
	 * 1) Token signature validation: perform the validation process for BES signature (see clause 6) with the time-stamp
	 * token. In all the steps of this process, take into account that the signature to validate is a timestamp token
	 * (e.g. to select TSA trust-anchors). If this step ends with a success indication, go to the next step. Otherwise,
	 * fail with the indication and information returned by the validation process.<br>
	 *
	 * 2) Data extraction: in addition to the data items returned in step 1, the process shall return data items
	 * extracted from the TSTInfo [11] (the generation time, the message imprint, etc.). These items may be used by the
	 * SVA in the process of validating the AdES signature.
	 *
	 * @param params
	 * @return
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

		prepareParameters(params);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");

		final XmlNode timestampValidationDataNode = mainNode.addChild(NodeName.TIMESTAMP_VALIDATION_DATA);

		for (final XmlDom signature : signatures) {

			final String type = signature.getValue("./@Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {

				params.setCurrentValidationPolicy(params.getCountersignatureValidationPolicy());
			} else {

				params.setCurrentValidationPolicy(params.getValidationPolicy());
			}
			constraintData = params.getCurrentValidationPolicy();

			final List<XmlDom> timestamps = new ArrayList<XmlDom>();
			final TimestampType[] timestampTypes = TimestampType.values();
			for (final TimestampType timestampType : timestampTypes) {

				extractTimestamp(signature, timestampType, timestamps);
			}
			if (timestamps.isEmpty()) {

				continue;
			}

			// This defines the signature context of the execution of the following processes.
			params.setSignatureContext(signature);

			final String signatureId = signature.getValue("./@Id");
			final XmlNode signatureNode = timestampValidationDataNode.addChild(NodeName.SIGNATURE);
			signatureNode.setAttribute(AttributeName.ID, signatureId);

			for (final XmlDom timestamp : timestamps) {

				final Conclusion conclusion = new Conclusion();

				// This defines the context of the execution of the following processes. The same sub-processes are used for
				// signature and timestamp validation.
				params.setContextName(NodeName.TIMESTAMP);
				params.setContextElement(timestamp);

				final String timestampId = timestamp.getValue("./@Id");
				final String timestampType = timestamp.getValue("./@Type");
				final XmlNode timestampNode = signatureNode.addChild(NodeName.TIMESTAMP);
				timestampNode.setAttribute(AttributeName.ID, timestampId);
				timestampNode.setAttribute(AttributeName.TIMESTAMP_TYPE, timestampType);

				/**
				 * 5. Basic Building Blocks
				 */
				final XmlNode basicBuildingBlocksNode = timestampNode.addChild(NodeName.BASIC_BUILDING_BLOCKS);

				/**
				 * 5.1. Identification of the signer's certificate (ISC)
				 */
				final IdentificationOfTheSignersCertificate isc = new IdentificationOfTheSignersCertificate();
				final Conclusion iscConclusion = isc.run(params, NodeName.TIMESTAMP);
				basicBuildingBlocksNode.addChild(iscConclusion.getValidationData());
				if (!iscConclusion.isValid()) {

					basicBuildingBlocksNode.addChild(iscConclusion.toXmlNode());
					continue;
				}
				conclusion.addInfo(iscConclusion);
				conclusion.addWarnings(iscConclusion);

				/**
				 * 5.2. Validation Context Initialisation (VCI)
				 */

				/*
				 * --> Not needed for Timestamps validation. The constraints are already loaded during the execution of the
				 * Basic Building Blocks process for the main signature.
				 */

				/**
				 * 5.4 Cryptographic Verification (CV)
				 */
				final CryptographicVerification cv = new CryptographicVerification();
				final Conclusion cvConclusion = cv.run(params, basicBuildingBlocksNode);
				if (!cvConclusion.isValid()) {

					basicBuildingBlocksNode.addChild(cvConclusion.toXmlNode());
					continue;
				}
				conclusion.addInfo(cvConclusion);
				conclusion.addWarnings(cvConclusion);

				/**
				 * 5.5 Signature Acceptance Validation (SAV)
				 */

				final Conclusion savConclusion = runSAV(timestamp, basicBuildingBlocksNode);
				if (!savConclusion.isValid()) {

					basicBuildingBlocksNode.addChild(savConclusion.toXmlNode());
					continue;
				}
				conclusion.addInfo(savConclusion);
				conclusion.addWarnings(savConclusion);

				/**
				 * 5.3 X.509 Certificate Validation (XCV)
				 */
				final X509CertificateValidation xcv = new X509CertificateValidation();
				final Conclusion xcvConclusion = xcv.run(params, NodeName.TIMESTAMP);
				basicBuildingBlocksNode.addChild(xcvConclusion.getValidationData());
				if (!xcvConclusion.isValid()) {

					basicBuildingBlocksNode.addChild(xcvConclusion.toXmlNode());
					continue;
				}
				conclusion.addInfo(xcvConclusion);
				conclusion.addWarnings(xcvConclusion);

				conclusion.setIndication(Indication.VALID);
				final XmlNode conclusionXmlNode = conclusion.toXmlNode();
				basicBuildingBlocksNode.addChild(conclusionXmlNode);
			}
		}
		final XmlDom tsDom = timestampValidationDataNode.toXmlDom();
		params.setTsData(tsDom);
		return tsDom;
	}

	/**
	 * This method extracts all timestamps from the {@code XmlDom} signature representation and adds them to the timestamp {@code List}
	 *
	 * @param signature     {@code XmlDom} representation of the signature
	 * @param timestampType
	 * @param timestamps    the {@code List} of the all extracted timestamps
	 */
	private void extractTimestamp(final XmlDom signature, final TimestampType timestampType, final List<XmlDom> timestamps) {

		final String xPath = "./Timestamps/Timestamp[@Type='%s']";
		final List<XmlDom> extractedTimestamps = signature.getElements(xPath, timestampType);
		timestamps.addAll(extractedTimestamps);
	}

	/**
	 * The SAV process for a timestamp is far simpler than that of the principal signature. This is why a specific method
	 * is dedicated to its treatment.
	 *
	 * @param timestampXmlDom
	 * @param processNode     the parent process {@code XmlNode} to use to include the validation information
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion runSAV(final XmlDom timestampXmlDom, final XmlNode processNode) {

		/**
		 * 5.5 Signature Acceptance Validation (SAV)
		 */

		final XmlNode subProcessNode = processNode.addChild(NodeName.SAV);

		final Conclusion conclusion = processSAV(timestampXmlDom, subProcessNode);

		final XmlNode conclusionXmlNode = conclusion.toXmlNode();
		subProcessNode.addChild(conclusionXmlNode);
		return conclusion;

	}

	/**
	 * 5.5.4 Processing<br>
	 *
	 * This process consists in checking the Signature and Cryptographic Constraints against the signature. The general
	 * principle is as follows: perform the following for each constraint:<br>
	 *
	 * • If the constraint necessitates processing a property/attribute in the signature, perform the processing of the
	 * property/attribute as specified from clause 5.5.4.1 to 5.5.4.8. <b>--> The DSS framework does not handle the
	 * constraints concerning timestamps.</b><br>
	 *
	 * • If at least one of the algorithms that have been used in validation of the signature or the size of the keys
	 * used with such an algorithm is no longer considered reliable, return
	 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE together with the list of algorithms and key sizes, if applicable,
	 * that are concerned and the time for each of the algorithms up to which the resp. algorithm was considered secure.
	 *
	 * @param timestampXmlDom
	 * @param subProcessNode
	 * @return the {@code Conclusion} which indicates the result of the process.
	 */
	private Conclusion processSAV(final XmlDom timestampXmlDom, final XmlNode subProcessNode) {

		final Conclusion conclusion = new Conclusion();

		final SignatureCryptographicConstraint signatureConstraint = constraintData.getSignatureCryptographicConstraint(NodeName.TIMESTAMP);
		if (signatureConstraint != null) {

			signatureConstraint.create(subProcessNode, MessageTag.ASCCM);
			signatureConstraint.setCurrentTime(currentTime);
			signatureConstraint.setEncryptionAlgorithm(timestampXmlDom.getValue(ValidationXPathQueryHolder.XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signatureConstraint.setDigestAlgorithm(timestampXmlDom.getValue(ValidationXPathQueryHolder.XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signatureConstraint.setKeyLength(timestampXmlDom.getValue(ValidationXPathQueryHolder.XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN));
			signatureConstraint.setIndications(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, MessageTag.EMPTY);
			signatureConstraint.setConclusionReceiver(conclusion);

			if (!signatureConstraint.check()) {

				return conclusion;
			}
		}

		final SignatureCryptographicConstraint signingCertificateConstraint = constraintData.getSignatureCryptographicConstraint(NodeName.TIMESTAMP, NodeName.SIGNING_CERTIFICATE);
		if (signingCertificateConstraint != null) {

			signingCertificateConstraint.create(subProcessNode, MessageTag.ASCCM);
			signingCertificateConstraint.setCurrentTime(currentTime);
			signingCertificateConstraint.setEncryptionAlgorithm(timestampXmlDom.getValue(ValidationXPathQueryHolder.XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signingCertificateConstraint.setDigestAlgorithm(timestampXmlDom.getValue(ValidationXPathQueryHolder.XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signingCertificateConstraint.setKeyLength(timestampXmlDom.getValue(ValidationXPathQueryHolder.XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN));
			signingCertificateConstraint.setIndications(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, MessageTag.EMPTY);
			signingCertificateConstraint.setConclusionReceiver(conclusion);

			if (!signingCertificateConstraint.check()) {

				return conclusion;
			}
		}

		// This validation process returns VALID
		conclusion.setIndication(Indication.VALID);
		return conclusion;
	}
}
