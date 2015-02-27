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

package eu.europa.ec.markt.dss.validation102853.processes.ltv;

import static eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.XPathSignature.getSigningCertificateId;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.PSV_IPCVC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.PSV_IPCVC_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.PSV_ITPOSVAOBCT;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.EtsiPOEExtraction;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

/**
 * 9.2.4 Past signature validation process<br>
 * <p/>
 * 9.2.4.1 Description<br>
 * <p/>
 * This process is used when validation of a signature (or a time-stamp token) fails at the current time with an
 * INDETERMINATE status such that the provided proofs of existence may help to go to a determined status.
 *
 * @author bielecro
 */
public class PastSignatureValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

	private static final Logger LOG = LoggerFactory.getLogger(PastSignatureValidation.class);

	/**
	 * // TODO: (Bob: 2014 Mar 12)
	 */
	private String contextName;

	private EtsiPOEExtraction poe;

	// returned data
	private XmlNode pastSignatureValidationData;

	private void prepareParameters(ProcessParameters params) {

		this.poe = (EtsiPOEExtraction) params.getPOE();
		isInitialised(params);
	}

	private void isInitialised(ProcessParameters params) {

		if (poe == null) {

			poe = new EtsiPOEExtraction();
			params.setPOE(poe);
		}
	}

	/**
	 * This method carry out the Past Signature Validation process.
	 * <p/>
	 * 9.2.1.2 Input<br>
	 * <p/>
	 * - Signature or time-stamp token . Mandatory<br>
	 * - Target certificate ............ Mandatory<br>
	 * - X.509 Validation Parameters ... Mandatory<br>
	 * - A set of POEs ................. Mandatory<br>
	 * - Certificate meta-data ......... Optional<br>
	 * - Chain Constraints ............. Optional<br>
	 * - Cryptographic Constraints ..... Optional<br>
	 *
	 * @param params
	 * @param signature                      Can be the document or the timestamp signature
	 * @param currentTimeSignatureConclusion
	 * @param context
	 */
	public PastSignatureValidationConclusion run(final ProcessParameters params, final XmlDom signature, final XmlDom currentTimeSignatureConclusion, final String context) {

		this.contextName = context;
		prepareParameters(params);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		pastSignatureValidationData = new XmlNode(PAST_SIGNATURE_VALIDATION_DATA);
		pastSignatureValidationData.setNameSpace(XmlDom.NAMESPACE);

		final PastSignatureValidationConclusion conclusion = process(params, signature, currentTimeSignatureConclusion);

		conclusion.setValidationData(pastSignatureValidationData);
		return conclusion;
	}

	private PastSignatureValidationConclusion process(final ProcessParameters params, final XmlDom signature, final XmlDom currentTimeSignatureConclusion) {

		final PastSignatureValidationConclusion conclusion = new PastSignatureValidationConclusion();

		final String signatureId = signature.getValue("./@Id");

		pastSignatureValidationData.setAttribute(ID, signatureId);

		final String currentTimeIndication = currentTimeSignatureConclusion.getValue("./Indication/text()");
		final String currentTimeSubIndication = currentTimeSignatureConclusion.getValue("./SubIndication/text()");

		/**
		 * 9.2.4.4 Processing<br>
		 *
		 * 1) Perform the past certificate validation process with the following inputs:<br>
		 * - the signature,<br>
		 * - the target certificate,<br>
		 * - the X.509 validation parameters,<br>
		 * - certificate meta-data,<br>
		 * - chain constraints,<br>
		 * - cryptographic constraints and<br>
		 * - the set of POEs.
		 */

		// --> run the past certificate validation
		final PastCertificateValidation pcv = new PastCertificateValidation();
		final PastCertificateValidationConclusion pcvConclusion = pcv.run(params, signature, contextName);

		pastSignatureValidationData.addChild(pcvConclusion.getValidationData());

		final Date controlTime = pcvConclusion.getControlTime();

		XmlNode constraintNode = addConstraint(PSV_IPCVC);

		boolean ok = VALID.equals(pcvConclusion.getIndication());
		constraintNode.addChild(STATUS, ok ? OK : KO);

		final XmlNode returnedPcvIndication;
		if (ok) {
			returnedPcvIndication = constraintNode.addChild(INFO);
		} else {

			returnedPcvIndication = constraintNode.addChild(ERROR, PSV_IPCVC_ANS);
		}
		returnedPcvIndication.setAttribute(INDICATION, pcvConclusion.getIndication());
		final String pcvSubIndication = pcvConclusion.getSubIndication();
		if (pcvSubIndication != null) {

			returnedPcvIndication.setAttribute(SUB_INDICATION, pcvSubIndication);
		}
		if (controlTime != null) {

			final String formatedControlTime = DSSUtils.formatDate(controlTime);
			returnedPcvIndication.setAttribute(CONTROL_TIME, formatedControlTime);
		}

		/**
		 * If it returns VALID/control-time, go to the next step. Otherwise, return the current time status and
		 * sub-indication with an explanation of the failure.<br>
		 */
		if (!ok) {

			conclusion.setIndication(currentTimeIndication);
			conclusion.setSubIndication(currentTimeSubIndication);
			conclusion.copyBasicInfo(returnedPcvIndication);//Info(pcvConclusion);
			return conclusion;
		}

		/**
		 * 2) If there is a POE of the signature value at (or before) control-time do the following:<br>
		 */

		constraintNode = addConstraint(PSV_ITPOSVAOBCT);

		final Date bestSignatureTime = poe.getLowestSignaturePOE(signatureId, controlTime);

		ok = bestSignatureTime != null;
		constraintNode.addChild(STATUS, ok ? OK : KO);

		if (ok) {

			final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
			constraintNode.addChild(INFO).setAttribute(BEST_SIGNATURE_TIME, formatedBestSignatureTime);

			/**
			 * -- If current time indication/sub-indication is INDETERMINATE/REVOKED_NO_POE or INDETERMINATE/
			 * REVOKED_CA_NO_POE, return VALID.<br>
			 */
			if (INDETERMINATE.equals(currentTimeIndication) && (REVOKED_NO_POE.equals(currentTimeSubIndication) || REVOKED_CA_NO_POE.equals(currentTimeSubIndication))) {

				conclusion.setIndication(VALID);
				return conclusion;
			}
			/**
			 * -- If current time indication/sub-indication is INDETERMINATE/OUT_OF_BOUNDS_NO_POE:<br>
			 */
			if (INDETERMINATE.equals(currentTimeIndication) && OUT_OF_BOUNDS_NO_POE.equals(currentTimeSubIndication)) {

				/**
				 * say best-signature-time is the lowest time at which there exists a POE for the signature value in the set
				 * of POEs:<br>
				 *
				 * --- a) If best-signature-time is before the issuance date of the signer's certificate (notBefore field),
				 * terminate with INVALID/NOT_YET_VALID.<br>
				 */

				final int signingCertId = getSigningCertificateId(signature);
				final XmlDom signingCert = params.getCertificate(signingCertId);
				final Date notBefore = signingCert.getTimeValue("./NotBefore/text()");

				if (bestSignatureTime.before(notBefore)) {

					conclusion.setIndication(INVALID);
					conclusion.setSubIndication(NOT_YET_VALID);
					return conclusion;
				} else {

					/**
					 * --- b) If best-signature-time is after the issuance date of the signer's certificate, return VALID.<br>
					 */
					conclusion.setIndication(VALID);
					return conclusion;
				}
			}

			/**
			 * -- If current time indication/sub-indication is INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and for each
			 * algorithm (or key size) in the list concerned by the failure, there is a POE for the material that uses this
			 * algorithm (or key size) at a time before to the time up to which the algorithm in question was considered
			 * secure, return VALID.<br>
			 */
			if (INDETERMINATE.equals(currentTimeIndication) && CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(currentTimeSubIndication)) {

				boolean poeExists = true;
				final List<XmlDom> infoList = currentTimeSignatureConclusion.getElements("./Info");
				for (final XmlDom info : infoList) {

					final String field = info.getValue("./@Field");
					if (!field.contains("/AlgoExpirationDate")) {

						poeExists = false;
						continue;
					}

					final String expirationDateString = info.getValue("./text()");
					if (ALGORITHM_NOT_FOUND.equals(expirationDateString)) {

						poeExists = false;
						continue;
					}
					final Date expirationDate = DSSUtils.parseDate(DSSUtils.DEFAULT_DATE_FORMAT, expirationDateString);
					final String context = info.getValue("./@Context");
					if (SIGNATURE.equals(context)) {

						Date poeDate_ = poe.getSignaturePOE(signatureId, expirationDate);
						if (poeDate_ == null) {

							poeExists = false;
							continue;
						}
					} else if (SIGNATURE.equals(context)) {

						//TODO:
					}
				}
				if (poeExists) {

					conclusion.setIndication(VALID);
					return conclusion;
				} else {

					conclusion.addInfo(infoList);
				}
			}
		}

		/**
		 * In all other cases, return current time indication/sub-indication together with an explanation of the failure.
		 */

		conclusion.setIndication(currentTimeIndication);
		conclusion.setSubIndication(currentTimeSubIndication);
		return conclusion;
	}

	/**
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final MessageTag messageTag) {

		XmlNode constraintNode = pastSignatureValidationData.addChild(CONSTRAINT);
		constraintNode.addChild(NAME, messageTag.getMessage()).setAttribute(NAME_ID, messageTag.name());
		return constraintNode;
	}
}
