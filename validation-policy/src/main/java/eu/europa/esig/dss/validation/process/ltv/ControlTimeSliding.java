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
package eu.europa.esig.dss.validation.process.ltv;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.RuleUtils;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;
import eu.europa.esig.dss.validation.policy.rules.NodeValue;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ValidationXPathQueryHolder;
import eu.europa.esig.dss.validation.process.dss.InvolvedServiceInfo;
import eu.europa.esig.dss.validation.process.subprocess.EtsiPOEExtraction;

/**
 * 9.2.2 Control-time sliding process<br>
 *
 * 9.2.2.1 Description<br>
 *
 * This process will slide the control-time from the current-time to some date in the past each time it encounters a
 * certificate proven to be revoked.
 *
 *
 *
 *         // Summary:<br>
 *         // - When the service status is not UNDERSUPERVISION then the closing date of this status need to be found.
 *         The class which handle this information need to be updated.<br>
 *         // The CRL extension expiredCertOnCRL should be taken into account during the revocation information
 *         retrieval.<br>
 *         // NOTE 4 is not completely taken into account.<br>
 *         // --> Closed
 */
public class ControlTimeSliding {

	private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(PastCertificateValidation.class);

	private ValidationPolicy constraintData;

	private Date controlTime;

	private EtsiPOEExtraction poe;

	// returned data
	private XmlNode controlTimeSlidingData;

	private void prepareParameters(final ProcessParameters params) {

		this.constraintData = params.getCurrentValidationPolicy();
		this.poe = (EtsiPOEExtraction) params.getPOE();
		isInitialised(params);
	}

	private void isInitialised(final ProcessParameters params) {

		if (poe == null) {

			poe = new EtsiPOEExtraction();
			params.setPOE(poe);
		}
	}

	/**
	 * 9.2.2.4 Processing<br>
	 *
	 * The following steps shall be performed:<br>
	 *
	 * @param params
	 */
	public ControlTimeSlidingConclusion run(final ProcessParameters params, final XmlDom certificateChain) {

		prepareParameters(params);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		controlTimeSlidingData = new XmlNode(NodeName.CONTROL_TIME_SLIDING_DATA);

		/**
		 * 1) Initialise control-time to the current date/time.<br>
		 */

		// The control-time is re-initialised at every turn
		controlTime = params.getCurrentTime();

		final ControlTimeSlidingConclusion conclusion = process(params, certificateChain);

		conclusion.setControlTime(controlTime);
		conclusion.setValidationData(controlTimeSlidingData);

		return conclusion;
	}

	/**
	 * This method returns the certificate id. This id is extracted either from the ChainCertificate, or Certificate.
	 *
	 * @param xmlDomObject
	 * @return
	 */
	private String getCertificateId(final XmlDom xmlDomObject) {
		final String certificateId = xmlDomObject.getValue("./@Id");
		return certificateId;
	}

	/**
	 * @param params
	 * @param certificateChain
	 * @return
	 */
	private ControlTimeSlidingConclusion process(final ProcessParameters params, final XmlDom certificateChain) {

		final ControlTimeSlidingConclusion conclusion = new ControlTimeSlidingConclusion();

		final String signingCertificateId = certificateChain.getValue("./ChainCertificate[1]/@Id");

		final List<XmlDom> chainCertificates = certificateChain.getElements("./ChainCertificate");

		Collections.reverse(chainCertificates);

		/**
		 * 2) For each certificate in the chain starting from the first certificate (the certificate issued by the trust
		 * anchor), do the following:<br>
		 */
		for (final XmlDom chainCertificate : chainCertificates) {

			final String certificateId = getCertificateId(chainCertificate);
			final XmlNode certificateNode = controlTimeSlidingData.addChild(AttributeValue.CERTIFICATE, StringUtils.EMPTY);
			certificateNode.setAttribute(AttributeValue.CERTIFICATE_ID, String.valueOf(certificateId));

			final XmlDom certificate = params.getCertificate(certificateId);

			final boolean isTrusted = certificate.getBoolValue("./Trusted/text()");
			if (isTrusted) {

				continue;
			}

			if (StringUtils.equals(signingCertificateId, certificateId)) {

				/**
				 * (See NOTE 1) Concerning the trust anchor, it must be checked if it is still trusted at the current
				 * date/time. Other checks are not necessary.<br>
				 */
				final XmlNode constraintNode = addConstraint(MessageTag.CTS_WITSS);

				final String status = InvolvedServiceInfo.getStatus(certificate);
				constraintNode.addChild(NodeName.STATUS, NodeValue.OK);
				constraintNode.addChild(NodeName.INFO).setAttribute(AttributeValue.TRUSTED_SERVICE_STATUS, status);

				final boolean underSupervision = InvolvedServiceInfo.isSERVICE_STATUS_UNDERSUPERVISION(NodeName.STATUS);
				final boolean supervisionInCessation = InvolvedServiceInfo.isSERVICE_STATUS_SUPERVISIONINCESSATION(NodeName.STATUS);
				final boolean accredited = InvolvedServiceInfo.isSERVICE_STATUS_ACCREDITED(NodeName.STATUS);

				if (!underSupervision && !supervisionInCessation && !accredited) {

					/**
					 * ...where the trust anchor is broken at a known date by initialising control-time to this date/time.<br>
					 */
					if (NodeName.STATUS.isEmpty()) {

						// Trusted service is unknown
						final String serviceName = InvolvedServiceInfo.getServiceName(certificate);
						LOG.warn("The status of the service is unknown: (serviceName: " + serviceName + ")");
					} else {

						final Date statusEndDate = InvolvedServiceInfo.getEndDate(certificate);
						controlTime = statusEndDate;
						addControlTime(constraintNode);
					}
				}
			}
			/**
			 * - a) Find revocation status information satisfying the following:<br>
			 * - - 􀀀 The revocation status information is consistent with the rules conditioning its use to check the
			 * revocation status of the considered certificate. For instance, in the case of a CRL, it shall satisfy the
			 * checks described in (see clause 6.3).<br>
			 *
			 * TODO: 20130704 by bielecro: To notify ETSI --> (see clause 6.3) is not the right clause.<br>
			 */

			XmlNode constraintNode = addConstraint(MessageTag.CTS_DRIE);

			final boolean revocationExists = certificate.exists("./Revocation");
			if (!revocationExists) {

				constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
				conclusion.setIndication(Indication.INDETERMINATE);
				conclusion.setSubIndication(SubIndication.NO_POE);
				return conclusion;
			}

			final Date revocationIssuingTime = certificate.getTimeValue("./Revocation/IssuingTime/text()");
			final String formatedRevocationIssuingTime = DSSUtils.formatDate(revocationIssuingTime);

			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);
			constraintNode.addChild(NodeName.INFO).setAttribute(AttributeName.REVOCATION_ISSUING_TIME, formatedRevocationIssuingTime);

			final Date notAfterTime = certificate.getTimeValue("./NotAfter/text()");
			final Date notBeforeTime = certificate.getTimeValue("./NotBefore/text()");

			/**
			 * (See NOTE 2)<br>
			 * TODO: ...(for instance, using the CRL extension expiredCertOnCRL (OID: 2.5.29.60)) This check need to be
			 * added to the revocation information retrieval.
			 */
			constraintNode = addConstraint(MessageTag.CTS_ICNEAIDORSI);

			if (revocationIssuingTime.before(notBeforeTime) || revocationIssuingTime.after(notAfterTime)) {

				constraintNode.addChild(NodeName.STATUS, NodeValue.KO);

				conclusion.setIndication(Indication.INDETERMINATE);
				conclusion.setSubIndication(SubIndication.NO_POE);
				return conclusion;
			}
			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);

			/**
			 * - - 􀀀 The issuance date of the revocation status information is before control-time. If more than one
			 * revocation status is found, consider the most recent one and go to the next step. If there is no such
			 * information, terminate with INDETERMINATE/NO_POE:<br>
			 */

			constraintNode = addConstraint(MessageTag.CTS_IIDORSIBCT);

			if (!revocationIssuingTime.before(controlTime)) {

				constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
				addControlTime(constraintNode);

				conclusion.setIndication(Indication.INDETERMINATE);
				conclusion.setSubIndication(SubIndication.NO_POE);
				return conclusion;
			}
			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);

			/**
			 * - b) If the set of POEs contains a proof of existence of the certificate and the revocation status
			 * information at (or before) control-time, go to step c). Otherwise, terminate with INDETERMINATE/NO_POE.
			 */

			constraintNode = addConstraint(MessageTag.CTS_DSOPCPOEOC);

			final boolean poeExists = poe.getCertificatePOE(certificateId, controlTime);
			if (!poeExists || (revocationIssuingTime.compareTo(controlTime) > 0)) {

				constraintNode.addChild(NodeName.STATUS, NodeValue.KO);
				conclusion.setIndication(Indication.INDETERMINATE);
				conclusion.setSubIndication(SubIndication.NO_POE);
				return conclusion;
			}
			constraintNode.addChild(NodeName.STATUS, NodeValue.OK);

			/**
			 * - c) Update the value of control-time as follows:<br>
			 */

			constraintNode = addConstraint(MessageTag.CTS_SCT);
			addControlTime(constraintNode);

			final boolean revoked = !certificate.getBoolValue("./Revocation/Status/text()");
			/**
			 * - - 􀀀 If the certificate is marked as revoked in the revocation status information, set control-time to the
			 * revocation date.<br>
			 */
			if (revoked) {

				final Date revocationDate = certificate.getTimeValue("./Revocation/DateTime/text()");
				controlTime = revocationDate;

				final String formatedRevocationDate = DSSUtils.formatDate(revocationDate);
				constraintNode.addChild(NodeName.INFO, NodeValue.CTS_CTSTRT_LABEL);
				constraintNode.addChild(NodeName.INFO).setAttribute(AttributeName.REVOCATION_TIME, formatedRevocationDate);
			} else {

				/**
				 * - - 􀀀 If the certificate is not marked as revoked.<br>
				 * - - - - If the revocation status information is not considered "fresh", set control-time to the issuance
				 * date of the revocation status information.<br>
				 */
				final long revocationDeltaTime = controlTime.getTime() - revocationIssuingTime.getTime();
				if (revocationDeltaTime > constraintData.getMaxRevocationFreshness()) {

					controlTime = revocationIssuingTime;
					constraintNode.addChild(NodeName.INFO, NodeValue.CTS_CTSTRIT_LABEL);
					final XmlNode xmlNode = constraintNode.addChild(NodeName.INFO, MessageTag.BBB_XCV_IRIF_ANS);
					xmlNode.setAttribute(AttributeValue.CERTIFICATE_ID, String.valueOf(certificateId)).setAttribute(AttributeName.REVOCATION_ISSUING_TIME, formatedRevocationIssuingTime);
				}

				/**
				 * - - - - Otherwise, the value of control-time is not changed.<br>
				 */
			}
			/**
			 * - d) Apply the cryptographic constraints to the certificate and the revocation status information. If the
			 * certificate (or the revocation status information) does not match these constraints, set control-time to the
			 * lowest time up to which the listed algorithms were considered reliable.<br>
			 */

			checkDigestAlgoExpirationDate(certificate, constraintNode, NodeValue.CTS_CTSTETOCSA_LABEL);
			checkEncryptionAlgoExpirationDate(certificate, constraintNode, NodeValue.CTS_CTSTETOCSA_LABEL);

			final XmlDom revocation = certificate.getElement("./Revocation");
			checkDigestAlgoExpirationDate(revocation, constraintNode, NodeValue.CTS_CTSTETORSA_LABEL);
			checkEncryptionAlgoExpirationDate(revocation, constraintNode, NodeValue.CTS_CTSTETORSA_LABEL);

			/**
			 * 3) Continue with the next certificate in the chain or, if no further certificate exists, terminate with
			 * VALID and the calculated control-time.<br>
			 */
		}
		/**
		 * NOTE 1: In step 1, initialising control-time with current date/time assumes that the trust anchor is still
		 * trusted at the current date/time. The algorithm can capture the very exotic case where the trust anchor is
		 * broken (or becomes untrusted for any other reason) at a known date by initialising control-time to this
		 * date/time.<br>
		 *
		 * NOTE 2: The rational of step 2-a) is to check that the revocation status information is "in-scope" for the
		 * given certificate. In other words, the rationale is to check that the revocation status information is reliable
		 * to be used to ascertain the revocation status of the given certificate. For instance, this includes the fact
		 * the certificate is not expired at the issuance date of the revocation status information, unless the issuing CA
		 * states that its issues revocation information status for expired certificates (for instance, using the CRL
		 * extension expiredCertOnCRL).<br>
		 *
		 * NOTE 3: If the certificate (or the revocation status information) was authentic, but the signature has been
		 * faked exploiting weaknesses of the algorithms used, this is assumed only to be possible after the date the
		 * algorithms are declared to be no longer acceptable. Therefore, the owner of the original key pair is assumed to
		 * having been under control of his key up to that date. This is the rational of sliding control-time in step
		 * 2-d).<br>
		 *
		 * NOTE 4: For more readability, the algorithm above implicitly assumes that the revocation information status is
		 * signed by the certificate's issuer which is the most traditional revocation setting but not the only one. The
		 * same algorithm can be adapted to the cases where the revocation information status has its own certificate
		 * chain by applying the control-time sliding process to this chain which would output a control-time that has to
		 * be compared to the control-time associated to the certificate.
		 */

		conclusion.setIndication(Indication.VALID);
		conclusion.addInfo().setAttribute(AttributeValue.CONTROL_TIME, DSSUtils.formatDate(controlTime));

		return conclusion;
	}

	/**
	 * @param constraintNode
	 */

	private void addControlTime(XmlNode constraintNode) {

		String formatedControlTime = DSSUtils.formatDate(controlTime);
		constraintNode.addChild(NodeName.INFO).setAttribute(AttributeValue.CONTROL_TIME, formatedControlTime);
	}

	/**
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final MessageTag messageTag) {

		XmlNode constraintNode = controlTimeSlidingData.addChild(NodeName.CONSTRAINT);
		constraintNode.addChild(NodeName.NAME, messageTag.getMessage()).setAttribute(AttributeName.NAME_ID, messageTag.name());
		return constraintNode;
	}

	private void checkEncryptionAlgoExpirationDate(final XmlDom token, final XmlNode infoContainerNode, final String message) {

		String encryptionAlgo = token.getValue(ValidationXPathQueryHolder.XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN);
		encryptionAlgo = RuleUtils.canonicalizeEncryptionAlgo(encryptionAlgo);
		final String encryptionKeyLength = token.getValue(ValidationXPathQueryHolder.XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN);
		final String algoWithKeyLength = encryptionAlgo + encryptionKeyLength;

		final Date algoExpirationDate = constraintData.getAlgorithmExpirationDate(algoWithKeyLength);
		if ((algoExpirationDate != null) && controlTime.after(algoExpirationDate)) {

			controlTime = algoExpirationDate;
			final String formatedCertAlgoExpirationDate = DSSUtils.formatDate(algoExpirationDate);
			infoContainerNode.addChild(NodeName.INFO, message);
			infoContainerNode.addChild(NodeName.INFO).setAttribute(AttributeValue.ALGORITHM_EXPIRATION_DATE, formatedCertAlgoExpirationDate);
		}
	}

	private void checkDigestAlgoExpirationDate(final XmlDom token, final XmlNode infoContainerNode, final String message) {

		String digestAlgo = token.getValue(ValidationXPathQueryHolder.XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN);
		digestAlgo = RuleUtils.canonicalizeSignatureAlgo(digestAlgo);
		final Date algoExpirationDate = constraintData.getAlgorithmExpirationDate(digestAlgo);
		if ((algoExpirationDate != null) && controlTime.after(algoExpirationDate)) {

			controlTime = algoExpirationDate;
			final String formatedCertAlgoExpirationDate = DSSUtils.formatDate(algoExpirationDate);
			infoContainerNode.addChild(NodeName.INFO, message);
			infoContainerNode.addChild(NodeName.INFO).setAttribute(AttributeValue.ALGORITHM_EXPIRATION_DATE, formatedCertAlgoExpirationDate);
		}
	}
}
