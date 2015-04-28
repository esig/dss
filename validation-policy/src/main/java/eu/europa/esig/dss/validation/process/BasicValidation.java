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

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.ExceptionMessage;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

/**
 * 6 Basic Validation Process<br>
 * This clause describes a validation process for basic short-term signature validation that is appropriate for
 * validating basic signatures (e.g. time-stamps, CRLs, etc.) as well as AdES-BES and AdES-EPES electronic signatures.
 * The process is built on the building blocks described in the previous clause.
 *
 *
 */
public class BasicValidation {

	private static final Logger LOG = LoggerFactory.getLogger(BasicValidation.class);

	// Secondary inputs
	/**
	 * See {@link eu.europa.esig.dss.validation.policy.ProcessParameters#getBasicBuildingBlocksReport()}
	 *
	 * @return
	 */
	private XmlDom basicBuildingBlocksReport;
	private XmlDom contentTimestampsAdESTValidationData;

	private void prepareParameters(final XmlNode mainNode, final ProcessParameters params) {

		this.basicBuildingBlocksReport = params.getBasicBuildingBlocksReport();
		isInitialised(mainNode, params);
	}

	private void isInitialised(final XmlNode mainNode, final ProcessParameters params) {

		if (basicBuildingBlocksReport == null) {

			/**
			 * The execution of the Basic Building Blocks validation process which creates the validation data.<br>
			 */
			final BasicBuildingBlocks basicBuildingBlocks = new BasicBuildingBlocks();
			basicBuildingBlocksReport = basicBuildingBlocks.run(mainNode, params);
		}
	}

	/**
	 * This method runs the Basic validation process.
	 *
	 * 6.2 Inputs<br>
	 * Signature ..................... Mandatory<br>
	 * Signed data object (s) ........ Optional<br>
	 * Signer's Certificate .......... Optional<br>
	 * Trusted-status Service Lists .. Optional<br>
	 * Signature Validation Policies . Optional<br>
	 * Local configuration ...........Optional<br>
	 *
	 * 6.3 Outputs<br>
	 * The main output of the signature validation is a status indicating the validity of the signature. This status may
	 * be accompanied by additional information (see clause 4).<br>
	 *
	 * 6.4 Processing<br>
	 * NOTE 1: Since processing is largely implementation dependent, the steps listed in this clause are not necessarily
	 * to be processed exactly in the order given. Any ordering that produces the same results can be used, even parallel
	 * processing is possible.<br>
	 *
	 * The following steps shall be performed:
	 *
	 * @param params
	 * @return
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

		prepareParameters(mainNode, params);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		final XmlNode basicValidationData = mainNode.addChild(NodeName.BASIC_VALIDATION_DATA);

		final List<XmlDom> signatures = basicBuildingBlocksReport.getElements("./Signature");
		for (final XmlDom signature : signatures) {

			final String signatureId = signature.getValue("./@Id");
			final String type = signature.getValue("./@Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {

				params.setCurrentValidationPolicy(params.getCountersignatureValidationPolicy());
			} else {

				params.setCurrentValidationPolicy(params.getValidationPolicy());
			}

			final XmlNode signatureNode = basicValidationData.addChild(NodeName.SIGNATURE);
			signatureNode.setAttribute(AttributeName.ID, signatureId);

			final XmlNode conclusionNode = signatureNode.addChild(NodeName.CONCLUSION);

			final boolean valid = process(signature, signatureId, conclusionNode);

			if (valid) {

				final XmlDom mainConclusion = signature.getElement("./Conclusion");
				if (mainConclusion == null) {

					throw new DSSException(ExceptionMessage.EXCEPTION_TWUEIVP);
				}
				conclusionNode.addChildrenOf(mainConclusion);
			}
		}

		final XmlDom bvDom = basicValidationData.toXmlDom();
		params.setBvData(bvDom);
		return bvDom;
	}

	/**
	 * @param signature      depicts the basic building blocks detailed validation report for a signature.
	 * @param signatureId    signature identifier
	 * @param conclusionNode {@code XmlNode} which is used to store the conclusion
	 * @return
	 */
	private boolean process(final XmlDom signature, final String signatureId, final XmlNode conclusionNode) {

		/**
		 * 1) Identify the signer's certificate: Perform the Signer's Certificate Identification process (see clause 5.1)
		 * with the signature and the signer's certificate, if provided as a parameter. If it returns INDETERMINATE,
		 * terminate with INDETERMINATE and associated information, otherwise go to the next step.
		 *
		 * TODO: (***) The ICS process can also return INVALID.FORMAT_FAILURE. This is not mentioned in the BVP process.
		 */
		final XmlDom iscConclusion = signature.getElement("./ISC/Conclusion");
		final String iscIndication = iscConclusion.getValue("./Indication/text()");

		if (!Indication.VALID.equals(iscIndication)) {

			conclusionNode.addChildrenOf(iscConclusion);
			return false;
		}

		/**
		 * 2) Initialise the validation constraints and parameters: Perform the Validation Context Initialisation process
		 * (see clause 5.2).
		 */

		final XmlDom vciConclusion = signature.getElement("./VCI/Conclusion");
		final String vciIndication = vciConclusion.getValue("./Indication/text()");

		if (!Indication.VALID.equals(vciIndication)) {

			conclusionNode.addChildrenOf(vciConclusion);
			return false;
		}

		/**
		 * 4) Verify the cryptographic signature value: Perform the Cryptographic Verification process with the following
		 * inputs:
		 *
		 * a) The signature.
		 *
		 * b) The certificate chain returned in the previous step.
		 *
		 * c) The signed data object(s).
		 *
		 * If the process returns VALID, go to the next step. Otherwise, terminate with the returned indication and
		 * associated information.
		 *
		 * --> We do this first to not be oblige to redo it at LTV process.
		 */
		final XmlDom cvConclusion = signature.getElement("./CV/Conclusion");
		final String cvIndication = cvConclusion.getValue("./Indication/text()");
		if (!Indication.VALID.equals(cvIndication)) {

			conclusionNode.addChildrenOf(cvConclusion);
			return false;
		}

		/**
		 * 5) Apply the validation constraints: Perform the Signature Acceptance Validation process with the following
		 * inputs:
		 *
		 * a) The signature.
		 *
		 * b) The Cryptographic Constraints.
		 *
		 * c) The Signature Constraints.
		 *
		 * 􀀀 If the process returns VALID, go to the next step.
		 *
		 * 􀀀 If the process returns INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by this
		 * failure is the signature value: If the signature contains a content-timestamp attribute, perform the Validation
		 * Process for AdES Time-Stamps as defined in clause 7. If it returns VALID and the algorithm(s) concerned were no
		 * longer considered reliable at the generation time of the time-stamp token, terminate with
		 * INVALID/CRYPTO_CONSTRAINTS_FAILURE. In all other cases, terminate with
		 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 *
		 * NOTE 2: The content time-stamp is a signed attribute and hence proves that the signature value was produced
		 * after the generation time of the time-stamp token.
		 *
		 * NOTE 3: In case this clause returns INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, LTV can be used to
		 * validate the signature, if other POE (e.g. from a trusted archive) exist.
		 *
		 * 􀀀 In all other cases, terminate with the returned indication and associated information.
		 *
		 * --> We do this first to not be oblige to redo it at LTV process.
		 */
		final XmlDom savConclusion = signature.getElement("./SAV/Conclusion");
		if (savConclusion == null) {

			throw new DSSException(ExceptionMessage.EXCEPTION_TWUEIVP);
		}
		final String savIndication = savConclusion.getValue("./Indication/text()");
		final String savSubIndication = savConclusion.getValue("./SubIndication/text()");

		if (Indication.INDETERMINATE.equals(savIndication) && SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(savSubIndication)) {

			List<XmlDom> contentTimestamps = signature.getElements("./ContentTimestamps/ProductionTime");
			if (contentTimestamps.isEmpty()) {

				conclusionNode.addChildrenOf(savConclusion);
				return false;
			}
			// To carry out content-timestamp AdES-T validation process.

			final XmlDom adestConclusion = contentTimestampsAdESTValidationData.getElement("/ContentTimestampsAdesTValidationData/Signature[@Id='%s']/Conclusion", signatureId);
			final String adestIndication = adestConclusion.getValue("./Indication/text()");
			if (!Indication.VALID.equals(adestIndication)) {

				conclusionNode.addChild(NodeName.INDICATION, Indication.INDETERMINATE);
				conclusionNode.addChild(NodeName.SUB_INDICATION, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
				return false;
			}
			boolean ok = true;
			final List<XmlDom> infoList = savConclusion.getElements("./Info");
			for (XmlDom info : infoList) {

				final String field = info.getValue("./@Field");
				if (field.contains("/AlgoExpirationDate/")) {

					final String expirationDateString = info.getValue("./text()");
					if (!AttributeValue.ALGORITHM_NOT_FOUND.equals(expirationDateString)) {

						// TODO: to be adapted to "./Info[@Field='TimestampProductionTime']/text()"
						final Date bestSignatureTime = adestConclusion.getTimeValue("./Info/@BestSignatureTime");

						final Date expirationDate = DSSUtils.parseDate(DSSUtils.DEFAULT_DATE_FORMAT, expirationDateString);
						if (expirationDate.before(bestSignatureTime)) {

							ok = false;
						}
					} else {

						ok = false;
					}
					break;
				}
			}
			if (ok) {

				conclusionNode.addChild(NodeName.INDICATION, Indication.INDETERMINATE);
				conclusionNode.addChild(NodeName.SUB_INDICATION, SubIndication.EXPIRED);
			} else {

				conclusionNode.addChild(NodeName.INDICATION, Indication.INVALID);
				conclusionNode.addChild(NodeName.SUB_INDICATION, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
			}
			return false;
		}
		if (!Indication.VALID.equals(savIndication)) {

			conclusionNode.addChildrenOf(savConclusion);
			return false;
		}

		/**
		 * 3) Validate the signer's certificate: Perform the X.509 Certificate Validation process (see clause 5.3) with
		 * the following inputs:
		 *
		 * a) The signature.<br>
		 *
		 * b) The signer's certificate obtained in step 1.<br>
		 *
		 * c) X.509 Validation Parameters, Certificate meta-data, Chain Constraints and Cryptographic Constraints obtained
		 * in step 2:<br>
		 */
		final XmlDom xcvConclusion = signature.getElement("./XCV/Conclusion");
		final String xcvIndication = xcvConclusion.getValue("./Indication/text()");
		final String xcvSubIndication = xcvConclusion.getValue("./SubIndication/text()");

		/**
		 * 􀀀 If the process returns VALID, go to the next step.
		 *
		 * 􀀀 If the process returns INDETERMINATE/REVOKED_NO_POE: If the signature contains a content-time-stamp
		 * attribute, perform the Validation Process for AdES Time-Stamps as defined in clause 7. If it returns VALID and
		 * the generation time of the time-stamp token is after the revocation time, terminate with INVALID/REVOKED. In
		 * all other cases, terminate with INDETERMINATE/REVOKED_NO_POE.
		 */
		if (Indication.INDETERMINATE.equals(xcvIndication) && SubIndication.REVOKED_NO_POE.equals(xcvSubIndication)) {

			XmlDom contentTimestamps = signature.getElement("./ContentTimestamps/ProductionTime");
			if (contentTimestamps != null) {

				final XmlDom adestConclusion = contentTimestampsAdESTValidationData.getElement("/ContentTimestampsAdesTValidationData/Signature[@Id='%s']/Conclusion", signatureId);
				final String adestIndication = adestConclusion.getValue("./Indication/text()");
				if (Indication.VALID.equals(adestIndication)) {

					final Date revocationTime = xcvConclusion.getTimeValue("./Info/@RevocationTime");
					final Date bestSignatureTime = adestConclusion.getTimeValue("./Info/@BestSignatureTime");

					if (bestSignatureTime.after(revocationTime)) {

						conclusionNode.addChild(NodeName.INDICATION, Indication.INVALID);
						conclusionNode.addChild(NodeName.SUB_INDICATION, SubIndication.REVOKED);
						return false;
					}
				}
			}
		}

		/**
		 * 􀀀 If the process returns INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If the signature contains a content-time-stamp
		 * attribute, perform the Validation Process for AdES Time-Stamps as defined in clause 7. If it returns VALID and
		 * the generation time of the time-stamp token is after the expiration date of the signer's certificate, terminate
		 * with INVALID/EXPIRED. In all other cases, terminate with INDETERMINATE/OUT_OF_BOUNDS_NO_POE.
		 */

		if (Indication.INDETERMINATE.equals(xcvIndication) && SubIndication.OUT_OF_BOUNDS_NO_POE.equals(xcvSubIndication)) {

			XmlDom contentTimestamps = signature.getElement("./ContentTimestamps/ProductionTime");

			if (contentTimestamps != null) {

				final XmlDom adestConclusionDom = contentTimestampsAdESTValidationData
						.getElement("/ContentTimestampsAdesTValidationData/Signature[@Id='%s']/Conclusion", signatureId);
				final String adestIndication = adestConclusionDom.getValue("./Indication/text()");
				if (Indication.VALID.equals(adestIndication)) {

					final Date bestSignatureTime = adestConclusionDom.getTimeValue("./Info/@BestSignatureTime");
					final Date notAfter = xcvConclusion.getTimeValue("./Info/@NotAfter");

					if (bestSignatureTime.after(notAfter)) {

						conclusionNode.addChild(NodeName.INDICATION, Indication.INVALID);
						conclusionNode.addChild(NodeName.SUB_INDICATION, SubIndication.EXPIRED);
						return false;
					}
				}
			}
		}

		/**
		 * 􀀀 In all other cases, terminate with the returned indication and associated information.
		 */

		if (!Indication.VALID.equals(xcvIndication)) {

			conclusionNode.addChildrenOf(xcvConclusion);
			return false;
		}

		/**
		 * 6) Data extraction: the SVA shall return the success indication VALID. In addition, the SVA should return
		 * additional information extracted from the signature and/or used by the intermediate steps. In particular, the
		 * SVA should provide to the DA all information related to signed and unsigned properties/attributes, including
		 * those which were not processed during the validation process. What the DA shall do with this information is out
		 * of the scope of the present document.
		 */

		return true;
	}
}
