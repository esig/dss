/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.processes;

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.EMPTY;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.policy.SignatureCryptographicConstraint;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.CryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.IdentificationOfTheSignersCertificate;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.X509CertificateValidation;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

/**
 * 7 Validation Process for Time-Stamps<br>
 * <br>
 * 7.1 Description<br>
 * <br>
 * This clause describes a process for the validation of an RFC 3161 [11] time-stamp token. An RFC 3161 [11] time-stamp
 * token is basically a CAdES-BES signature. Hence, the validation process is built in the validation process of a
 * CAdES-BES signature.<br>
 *
 * @author bielecro
 */
public class TimestampValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage, ValidationXPathQueryHolder {

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
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (params.getValidationPolicy() == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (currentTime == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "currentTime"));
		}
	}

	/**
	 * 7.4 Processing<br>
	 * <p/>
	 * The following steps shall be performed:<br>
	 * <p/>
	 * 1) Token signature validation: perform the validation process for BES signature (see clause 6) with the time-stamp
	 * token. In all the steps of this process, take into account that the signature to validate is a timestamp token
	 * (e.g. to select TSA trust-anchors). If this step ends with a success indication, go to the next step. Otherwise,
	 * fail with the indication and information returned by the validation process.<br>
	 * <p/>
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

		final XmlNode timestampValidationDataNode = mainNode.addChild(TIMESTAMP_VALIDATION_DATA);

		for (final XmlDom signature : signatures) {

			final String type = signature.getValue("./@Type");
			if (COUNTERSIGNATURE.equals(type)) {

				params.setCurrentValidationPolicy(params.getCountersignatureValidationPolicy());
			} else {

				params.setCurrentValidationPolicy(params.getValidationPolicy());
			}
			constraintData = params.getCurrentValidationPolicy();

			final List<XmlDom> timestamps = new ArrayList<XmlDom>();
			final TimestampType[] timestampTypes = TimestampType.values();
			for (int ii = 0; ii < timestampTypes.length; ii++) {

				final TimestampType timestampType = timestampTypes[ii];
				extractTimestamp(signature, timestampType, timestamps);
			}
			if (timestamps.isEmpty()) {

				continue;
			}

			// This defines the signature context of the execution of the following processes.
			params.setSignatureContext(signature);

			final String signatureId = signature.getValue("./@Id");
			final XmlNode signatureNode = timestampValidationDataNode.addChild(SIGNATURE);
			signatureNode.setAttribute(ID, signatureId);

			for (final XmlDom timestamp : timestamps) {

				final Conclusion conclusion = new Conclusion();

				// This defines the context of the execution of the following processes. The same sub-processes are used for
				// signature and timestamp validation.
				params.setContextName(TIMESTAMP);
				params.setContextElement(timestamp);

				final String timestampId = timestamp.getValue("./@Id");
				final String timestampType = timestamp.getValue("./@Type");
				final XmlNode timestampNode = signatureNode.addChild(TIMESTAMP);
				timestampNode.setAttribute(ID, timestampId);
				timestampNode.setAttribute(TIMESTAMP_TYPE, timestampType);

				/**
				 * 5. Basic Building Blocks
				 */
				final XmlNode basicBuildingBlocksNode = timestampNode.addChild(BASIC_BUILDING_BLOCKS);

				/**
				 * 5.1. Identification of the signer's certificate (ISC)
				 */
				final IdentificationOfTheSignersCertificate isc = new IdentificationOfTheSignersCertificate();
				final Conclusion iscConclusion = isc.run(params, TIMESTAMP);
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
				final Conclusion xcvConclusion = xcv.run(params, TIMESTAMP);
				basicBuildingBlocksNode.addChild(xcvConclusion.getValidationData());
				if (!xcvConclusion.isValid()) {

					basicBuildingBlocksNode.addChild(xcvConclusion.toXmlNode());
					continue;
				}
				conclusion.addInfo(xcvConclusion);
				conclusion.addWarnings(xcvConclusion);

				conclusion.setIndication(VALID);
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

		final XmlNode subProcessNode = processNode.addChild(SAV);

		final Conclusion conclusion = processSAV(timestampXmlDom, subProcessNode);

		final XmlNode conclusionXmlNode = conclusion.toXmlNode();
		subProcessNode.addChild(conclusionXmlNode);
		return conclusion;

	}

	/**
	 * 5.5.4 Processing<br>
	 * <p/>
	 * This process consists in checking the Signature and Cryptographic Constraints against the signature. The general
	 * principle is as follows: perform the following for each constraint:<br>
	 * <p/>
	 * • If the constraint necessitates processing a property/attribute in the signature, perform the processing of the
	 * property/attribute as specified from clause 5.5.4.1 to 5.5.4.8. <b>--> The DSS framework does not handle the
	 * constraints concerning timestamps.</b><br>
	 * <p/>
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

		final SignatureCryptographicConstraint signatureConstraint = constraintData.getSignatureCryptographicConstraint(TIMESTAMP);
		if (signatureConstraint != null) {

			signatureConstraint.create(subProcessNode, ASCCM);
			signatureConstraint.setCurrentTime(currentTime);
			signatureConstraint.setEncryptionAlgorithm(timestampXmlDom.getValue(XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signatureConstraint.setDigestAlgorithm(timestampXmlDom.getValue(XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signatureConstraint.setKeyLength(timestampXmlDom.getValue(XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN));
			signatureConstraint.setIndications(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, EMPTY);
			signatureConstraint.setConclusionReceiver(conclusion);

			if (!signatureConstraint.check()) {

				return conclusion;
			}
		}

		final SignatureCryptographicConstraint signingCertificateConstraint = constraintData.getSignatureCryptographicConstraint(TIMESTAMP, SIGNING_CERTIFICATE);
		if (signingCertificateConstraint != null) {

			signingCertificateConstraint.create(subProcessNode, ASCCM);
			signingCertificateConstraint.setCurrentTime(currentTime);
			signingCertificateConstraint.setEncryptionAlgorithm(timestampXmlDom.getValue(XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signingCertificateConstraint.setDigestAlgorithm(timestampXmlDom.getValue(XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN));
			signingCertificateConstraint.setKeyLength(timestampXmlDom.getValue(XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN));
			signingCertificateConstraint.setIndications(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, EMPTY);
			signingCertificateConstraint.setConclusionReceiver(conclusion);

			if (!signingCertificateConstraint.check()) {

				return conclusion;
			}
		}

		// This validation process returns VALID
		conclusion.setIndication(VALID);
		return conclusion;
	}
}
