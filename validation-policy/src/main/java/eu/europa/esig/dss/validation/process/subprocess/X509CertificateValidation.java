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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DateUtils;
import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.RevocationWrapper;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.CertificateExpirationConstraint;
import eu.europa.esig.dss.validation.policy.Constraint;
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
import eu.europa.esig.dss.validation.process.dss.ForLegalPerson;
import eu.europa.esig.dss.validation.process.dss.QualifiedCertificate;
import eu.europa.esig.dss.validation.process.dss.SSCD;
import eu.europa.esig.dss.validation.report.Conclusion;
import eu.europa.esig.dss.validation.report.DiagnosticDataWrapper;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;

public class X509CertificateValidation {

	/**
	 * The following variables are used only in order to simplify the writing of the rules!
	 */

	/**
	 * See {@link ProcessParameters#getDiagnosticData()}
	 */
	protected DiagnosticDataWrapper diagnosticData;

	/**
	 * See {@link ProcessParameters#getCurrentValidationPolicy()}
	 */
	protected ValidationPolicy constraintData;

	/**
	 * See {@link ProcessParameters#getCurrentTime()}
	 */
	private Date currentTime;

	/**
	 * See {@link ProcessParameters#getSignatureContext()}
	 */
	private SignatureWrapper signatureContext;

	/**
	 * See {@link ProcessParameters#getContextElement()}
	 */
	protected TokenProxy contextElement;

	/**
	 * // TODO: (Bob: 2014 Mar 12)
	 */
	private String contextName;

	/**
	 * See {@link ProcessParameters#getSigningCertificate()}
	 */
	private CertificateWrapper signingCertificate;

	/**
	 * This node is used to add the constraint nodes.
	 */
	protected XmlNode validationDataXmlNode;

	private void prepareParameters(final ProcessParameters params) {

		this.diagnosticData = params.getDiagnosticData();
		this.constraintData = params.getCurrentValidationPolicy();

		this.signatureContext = params.getSignatureContext();
		this.contextElement = params.getContextElement();
		this.currentTime = params.getCurrentTime();

		this.signingCertificate = params.getSigningCertificate();

		isInitialised(params);
	}

	private void isInitialised(final ProcessParameters params) {

		if (diagnosticData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (constraintData == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (currentTime == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "currentTime"));
		}
		if (signatureContext == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signatureContext"));
		}
		if (contextElement == null) {
			throw new DSSException(String.format(ExceptionMessage.EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "contextElement"));
		}
		/*
		    --> With the Warning system everything is possible
		    if (signingCertificateId == null) {
		        throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signCertId"));
		    }
		    if (signingCertificate == null) {
		        throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signCert"));
		    }
		 */
	}

	/**
	 * 5.3 X.509 Certificate Validation (XCV)<br>
	 * This method carry out the XCV process.
	 *
	 * @param params
	 *            validation process parameters
	 * @return false if the validation failed, true otherwise
	 */
	public Conclusion run(final ProcessParameters params, final String contextName) {

		this.contextName = contextName;
		prepareParameters(params);

		validationDataXmlNode = new XmlNode(NodeName.XCV);
		validationDataXmlNode.setNameSpace(XmlDom.NAMESPACE);

		final Conclusion conclusion = process(params);

		conclusion.setValidationData(validationDataXmlNode);
		return conclusion;
	}

	/**
	 * 5.3.4 Processing This process consists in the following steps:
	 *
	 * @param params
	 *            validation process parameters
	 * @return
	 */
	private Conclusion process(final ProcessParameters params) {

		final Conclusion conclusion = new Conclusion();

		/**
		 * 1) Check that the current time is in the validity range of the signer's certificate. If this constraint is not
		 * satisfied, abort the processing with the indication INDETERMINATE and the sub indication OUT_OF_BOUNDS_NO_POE.
		 */
		if (!checkCertificateExpirationConstraint(conclusion, contextName, NodeName.SIGNING_CERTIFICATE)) {
			return conclusion;
		}

		/**
		 * 2) Build a new prospective certificate chain that has not yet been evaluated. The chain shall satisfy the
		 * conditions of a prospective certificate chain as stated in [4], clause 6.1, using one of the trust anchors
		 * provided in the inputs:
		 */

		final boolean trustedProspectiveCertificateChain = isTrustedProspectiveCertificateChain(params);
		if (!checkProspectiveCertificateChainConstraint(conclusion, trustedProspectiveCertificateChain)) {
			return conclusion;
		}

		/**
		 * b) Otherwise, add this chain to the set of prospected chains and go to step 3.
		 */

		/**
		 * 3) Run the Certification Path Validation [4], clause 6.1, with the following inputs:<br>
		 * - the prospective chain built in the previous step,<br>
		 * - the trust anchor used in the previous step,<br>
		 * - the X.509 parameters provided in the inputs and<br>
		 * - the current date/time.<br>
		 * The validation shall include revocation checking for each certificate in the chain:
		 */

		List<XmlChainCertificate> certificateChain = contextElement.getCertificateChain();
		if (CollectionUtils.isNotEmpty(certificateChain)) {
			for (XmlChainCertificate item : certificateChain) {
				final String certificateId = item.getId();
				CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(certificateId);

				final boolean isTrusted = certificate.isTrusted();
				if (isTrusted) {
					continue;
				}

				final String subContext;
				// The case of other certificates then the signing certificate:
				if (!signingCertificate.getId().equals(certificateId)) {
					subContext = NodeName.CA_CERTIFICATE;
					// The check is already done for the signing certificate.
					// TODO: (Bob: 2014 Mar 09) Notify ETSI: This step is not indicated in the standard!!!
					if (!checkCertificateExpirationConstraint(conclusion, contextName, subContext)) {
						return conclusion;
					}
				} else {
					subContext = NodeName.SIGNING_CERTIFICATE;
					if (!checkKeyUsageConstraint(conclusion, certificate)) {
						return conclusion;
					}
				}

				if (!checkCertificateSignatureConstraint(conclusion, certificate, subContext)) {
					return conclusion;
				}

				if (!checkRevocationDataAvailableConstraint(conclusion, certificate, subContext)) {
					return conclusion;
				}

				if (!checkRevocationDataIsTrustedConstraint(conclusion, certificate, subContext)) {
					return conclusion;
				}
				//            final String revocationSource = certificateXmlDom.getValue("./Revocation/Source/text()");
				//            final String revocationSigningCertificateId = certificateXmlDom.getValue("./Revocation/SigningCertificate/@Id");
				//            final String anchorId = certificateXmlDom.getValue("./Revocation/CertificateChain/ChainCertificate[last()]/@Id");
				//            if ("OCSPToken".equals(revocationSource)) {
				//
				//            } else if ("CRLToken".equals(revocationSource)) {
				//
				//            }

				final RevocationWrapper revocation = certificate.getRevocationData();
				if (revocation != null) {
					boolean revocationFresh = prepareRevocationFreshnessCheck(revocation);

					/**
					 * a) If the certificate path validation returns a success indication and the revocation information used is
					 * considered fresh, go to the next step.
					 */

					/*
					 * --> This is done when other conditions are not met
					 */

					/**
					 * b) If the certificate path validation returns a success indication and the revocation information used is
					 * not considered fresh, abort the process with the indication INDETERMINATE, the sub indication TRY_LATER and
					 * the content of the NEXT_UPDATE-field of the CRL used as the suggestion for when to try the validation again.
					 */

					if (!checkRevocationFreshnessConstraint(conclusion, certificateId, revocationFresh, revocation, subContext)) {
						return conclusion;
					}


					// The case of the signing certificate:
					if (signingCertificate.getId().equals(certificateId)) {

						if (!checkSigningCertificateRevokedConstraint(conclusion, certificateId, revocation, subContext)) {
							return conclusion;
						}

						if (!checkSigningCertificateOnHoldConstraint(conclusion, certificateId, revocation,	subContext)) {
							return conclusion;
						}

						if (!checkSigningCertificateTSLValidityConstraint(conclusion, certificate)) {
							return conclusion;
						}

						if (!checkSigningCertificateTSLStatusConstraint(conclusion, certificate)) {
							return conclusion;
						}

						if (!checkSigningCertificateTSLStatusAndValidityConstraint(conclusion, certificate)) {
							return conclusion;
						}
						// There is not need to check the revocation data for trusted and self-signed certificates
					} else {

						// For all certificates different from the signing certificate and trust anchor.

						if (!checkIntermediateCertificateRevokedConstraint(conclusion, certificateId, revocation, subContext)) {
							return conclusion;
						}
					}

					// revocation data signature cryptographic constraints validation
					if (!checkCertificateCryptographicConstraint(conclusion, revocation, AttributeValue.REVOCATION, subContext)) {
						return conclusion;
					}

				}
				/**
				 * f) If the certificate path validation returns a failure indication with any other reason, go to step 2.
				 */
				// --> DSS builds only one chain

			} // loop end
		}

		if (!checkChainConstraint(conclusion)) {
			return conclusion;
		}

		/**
		 * A.2 Constraints on X.509 Certificate meta-data
		 * The following constraints are to be applied to the signer's certificate before considering it as valid for the
		 * intended use.
		 * --> These constraints apply only to the main signature
		 */
		if (NodeName.MAIN_SIGNATURE.equals(contextName)) {

			final QualifiedCertificate qc = new QualifiedCertificate();
			final boolean isQC = qc.run(signingCertificate);
			if (!checkSigningCertificateQualificationConstraint(conclusion, isQC)) {
				return conclusion;
			}

			final SSCD sscd = new SSCD();
			final Boolean isSSCD = sscd.run(signingCertificate);
			if (!checkSigningCertificateSupportedBySSCDConstraint(conclusion, isSSCD)) {
				return conclusion;
			}

			final ForLegalPerson forLegalPerson = new ForLegalPerson();
			final Boolean isForLegalPerson = forLegalPerson.run(signingCertificate);
			if (!checkSigningCertificateIssuedToLegalPersonConstraint(conclusion, isForLegalPerson)) {
				return conclusion;
			}
		}

		/**
		 * 5) Apply the cryptographic constraints to the chain. If the chain does not match these constraints, set the
		 * current status to INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and go to step 2.
		 */
		final String lastChainCertId = contextElement.getLastChainCertificateId();
		for (final XmlChainCertificate certToken : certificateChain) {

			final String certificateId = certToken.getId();
			if (certificateId.equals(lastChainCertId) && trustedProspectiveCertificateChain) {

				/**
				 * The trusted anchor is not checked. In the case of a certificate chain consisting of a single certificate
				 * which is trusted we need to set this variable to true.
				 */
				continue;
			}

			final CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(certificateId);
			final String subContext = certificateId.equals(signingCertificate.getId()) ? NodeName.SIGNING_CERTIFICATE : NodeName.CA_CERTIFICATE;

			// certificate signature cryptographic constraints validation
			if (!checkCertificateCryptographicConstraint(conclusion, certificate, contextName, subContext)) {
				return conclusion;
			}
		}
		// This validation process returns VALID
		conclusion.setIndication(Indication.VALID);
		return conclusion;
	}

	/**
	 * Preparation of information about revocation data and their freshness.
	 *
	 * @param revocation
	 * @return
	 */
	private boolean prepareRevocationFreshnessCheck(RevocationWrapper revocation) {
		boolean revocationFreshnessToBeChecked = constraintData.isRevocationFreshnessToBeChecked();
		boolean revocationFresh = !revocationFreshnessToBeChecked;

		Date issuingTime = revocation.getIssuingTime();
		if (revocationFreshnessToBeChecked && (issuingTime != null)) {
			final long revocationDeltaTime = currentTime.getTime() - issuingTime.getTime();
			if (revocationDeltaTime <= constraintData.getMaxRevocationFreshness()) {
				revocationFresh = true;
			}
		}
		return revocationFresh;
	}

	/**
	 * This method checks that the current time is in the validity range of the certificate. If this constraint is not
	 * satisfied, abort the processing with the indication INDETERMINATE and the sub indication OUT_OF_BOUNDS_NO_POE.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param context
	 * @param subContext
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkCertificateExpirationConstraint(final Conclusion conclusion, final String context, final String subContext) {

		final CertificateExpirationConstraint constraint = constraintData.getSigningCertificateExpirationConstraint(context, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_ICTIVRSC);
		constraint.setCurrentTime(currentTime);
		constraint.setNotAfter(signingCertificate.getNotAfter());
		constraint.setNotBefore(signingCertificate.getNotBefore());
		constraint.setExpiredCertsRevocationInfo(getDate(signingCertificate, "./TrustedServiceProvider/ExpiredCertsRevocationInfo"));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.OUT_OF_BOUNDS_NO_POE, MessageTag.BBB_XCV_ICTIVRSC_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * a) If no new chain can be built, abort the processing with the current status and the last chain built or, if
	 * no chain was built, with INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param trustedProspectiveCertificateChain
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	protected boolean checkProspectiveCertificateChainConstraint(final Conclusion conclusion, boolean trustedProspectiveCertificateChain) {

		final Constraint constraint = constraintData.getProspectiveCertificateChainConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_CCCBB);
		constraint.setValue(trustedProspectiveCertificateChain);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.NO_CERTIFICATE_CHAIN_FOUND, MessageTag.BBB_XCV_CCCBB_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	protected boolean isTrustedProspectiveCertificateChain(final ProcessParameters params) {
		final String lastChainCertId = contextElement.getLastChainCertificateId();
		final CertificateWrapper lastChainCertificate = diagnosticData.getUsedCertificateByIdNullSafe(lastChainCertId);
		return lastChainCertificate.isTrusted();
	}

	/**
	 * Retrieves the {@code Date} from an {@code XmlNode} using the XPath query.
	 *
	 * @param xmlDom
	 *            {@code XmlDom} containing the desired date.
	 * @param xPathQuery
	 *            XPath query to run
	 * @return {@code Date} or null if the XPath query returns no element or if the date conversion is impossible.
	 */
	private Date getDate(final XmlDom xmlDom, final String xPathQuery) {

		final String formatedDate = xmlDom.getValue(xPathQuery + "/text()");
		try {
			return DateUtils.parseDate(formatedDate);
		} catch (DSSException e) {
			return null;
		}
	}

	/**
	 * This method checks the signature of the given certificate.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificate
	 * @param subContext
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkCertificateSignatureConstraint(final Conclusion conclusion, final CertificateWrapper certificate, final String subContext) {

		final Constraint constraint = constraintData.getCertificateSignatureConstraint(contextName, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_ICSI);
		constraint.setValue(certificate.isSignatureValid());
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.NO_CERTIFICATE_CHAIN_FOUND, MessageTag.BBB_XCV_ICSI_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks the revocation data is available for the given certificate.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificate
	 * @param subContext
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkRevocationDataAvailableConstraint(final Conclusion conclusion, final CertificateWrapper certificate, String subContext) {

		final Constraint constraint = constraintData.getRevocationDataAvailableConstraint(contextName, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_IRDPFC);
		constraint.setValue(certificate.isRevocationDataAvailable());
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.BBB_XCV_IRDPFC_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the revocation data is trusted for the given certificate.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param xmlCertificate
	 * @param subContext
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkRevocationDataIsTrustedConstraint(Conclusion conclusion, CertificateWrapper certificate, String subContext) {

		final Constraint constraint = constraintData.getRevocationDataIsTrustedConstraint(contextName, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_IRDTFC);
		String anchorSource = null;
		RevocationWrapper revocationData = certificate.getRevocationData();
		if (revocationData != null){
			anchorSource = revocationData.getLastChainCertificateSource();
		}
		final CertificateSourceType anchorSourceType = StringUtils.isBlank(anchorSource) ? CertificateSourceType.UNKNOWN : CertificateSourceType.valueOf(anchorSource);
		constraint.setValue(isRevocationDataTrusted(anchorSourceType));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.BBB_XCV_IRDTFC_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setAttribute(AttributeValue.CERTIFICATE_SOURCE, anchorSource);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	private String isRevocationDataTrusted(final CertificateSourceType anchorSourceType) {
		final boolean trusted = CertificateSourceType.TRUSTED_LIST.equals(anchorSourceType) || CertificateSourceType.TRUSTED_STORE.equals(anchorSourceType);
		return String.valueOf(trusted);
	}

	/**
	 * This method checks if the revocation data is fresh for the given certificate. If the revocation data does not exist then this check is ignored.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param revocationFresh
	 * @param revocation
	 * @param subContext
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkRevocationFreshnessConstraint(final Conclusion conclusion, final String certificateId, final boolean revocationFresh, final RevocationWrapper revocation, String subContext) {

		// If the revocation data does not exist then this check is ignored.
		if (revocation.getIssuingTime() == null) {
			return true;
		}

		final Constraint constraint = constraintData.getRevocationDataFreshnessConstraint(contextName, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_IRIF);
		constraint.setValue(String.valueOf(revocationFresh));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.BBB_XCV_IRIF_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificateId);
		constraint.setAttribute(AttributeName.REVOCATION_NEXT_UPDATE, revocation.getNextUpdate());
		constraint.setAttribute(AttributeName.REVOCATION_ISSUING_TIME, revocation.getIssuingTime());
		constraint.setAttribute(AttributeName.MAXIMUM_REVOCATION_FRESHNESS, constraintData.getFormatedMaxRevocationFreshness());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the signing certificate has an appropriate key usage.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param certificateXmlDom
	 * @return
	 */
	private boolean checkKeyUsageConstraint(Conclusion conclusion, CertificateWrapper certificate) {
		final Constraint constraint = constraintData.getSigningCertificateKeyUsageConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_ISCGKU);
		constraint.setValue(certificate.getKeyUsages());
		constraint.setIndications(Indication.INVALID, SubIndication.SIG_CONSTRAINTS_FAILURE, MessageTag.BBB_XCV_ISCGKU_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setConclusionReceiver(conclusion);
		return constraint.checkInList();
	}

	/**
	 * This method checks if the signing certificate is revoked.
	 * c) If the certificate path validation returns a failure indication because the signer's certificate has
	 * been determined to be revoked, abort the process with the indication INDETERMINATE, the sub indication
	 * REVOKED_NO_POE, the validated chain, the revocation date and the reason for revocation.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param revocation
	 * @return false if the check failed and the process should stop, true otherwise.
	 * @param subContext
	 */
	private boolean checkSigningCertificateRevokedConstraint(final Conclusion conclusion, final String certificateId, RevocationWrapper revocation, String subContext) {

		final Constraint constraint = constraintData.getSigningCertificateRevokedConstraint(contextName, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_ISCR);
		final boolean revoked = !revocation.isStatus() && !CRLReasonEnum.certificateHold.name().equals(revocation.getReason());
		constraint.setValue(String.valueOf(revoked));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.REVOKED_NO_POE, MessageTag.BBB_XCV_ISCR_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificateId);
		if (revocation.getDateTime() != null) {
			constraint.setAttribute(AttributeName.REVOCATION_TIME, revocation.getDateTime());
		}
		if (StringUtils.isNotBlank(revocation.getReason())) {
			constraint.setAttribute(AttributeName.REVOCATION_REASON, revocation.getReason());
		}
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the signing certificate is on hold.
	 * d) If the certificate path validation returns a failure indication because the signer's certificate has
	 * been determined to be on hold, abort the process with the indication INDETERMINATE, the sub indication
	 * TRY_LATER, the suspension time and, if available, the content of the NEXT_UPDATE-field of the CRL used as
	 * the suggestion for when to try the validation again.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param revocationStatus
	 * @param revocationReason
	 * @param revocationDatetime
	 * @param revocationNextUpdate
	 * @param subContext
	 * @return
	 */
	private boolean checkSigningCertificateOnHoldConstraint(final Conclusion conclusion, final String certificateId, final RevocationWrapper revocation, String subContext) {

		final Constraint constraint = constraintData.getSigningCertificateOnHoldConstraint(contextName, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_ISCOH);
		final boolean onHold = !revocation.isStatus() && CRLReasonEnum.certificateHold.name().equals(revocation.getReason());
		constraint.setValue(String.valueOf(onHold));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.BBB_XCV_ISCOH_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificateId);
		if (revocation.getDateTime() != null) {
			constraint.setAttribute(AttributeName.REVOCATION_TIME, revocation.getDateTime());
		}
		if (revocation.getNextUpdate() != null) {
			constraint.setAttribute(AttributeName.REVOCATION_NEXT_UPDATE, revocation.getNextUpdate());
		}
		constraint.setConclusionReceiver(conclusion);
		return constraint.check();
	}

	/**
	 * This method checks if the TSL validity is in concordance with the signing certificate .
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param certificateXmlDom
	 * @return
	 */
	private boolean checkSigningCertificateTSLValidityConstraint(final Conclusion conclusion, final CertificateWrapper certificate) {

		final String trustedSource = certificate.getLastChainCertificateSource();
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		final Constraint constraint = constraintData.getSigningCertificateTSLValidityConstraint(contextName);
		if (constraint == null) {
			return true;
		}

		constraint.create(validationDataXmlNode, MessageTag.CTS_IIDOCWVPOTS);

		final Date certificateValidFrom = certificate.getNotBefore();
		List<XmlTrustedServiceProviderType> tspList = diagnosticData.getCertificateTSPService(xmlCertificate);
		boolean found = false;
		for (final XmlTrustedServiceProviderType trustedServiceProvider : tspList) {

			final String serviceTypeIdentifier = trustedServiceProvider.getTSPServiceType();
			if (!TSLConstant.CA_QC.equals(serviceTypeIdentifier)) {
				continue;
			}
			final Date statusStartDate = trustedServiceProvider.getStartDate();
			final Date statusEndDate = trustedServiceProvider.getEndDate();
			// The issuing time of the certificate should be into the validity period of the associated service
			if (certificateValidFrom.after(statusStartDate) && ((statusEndDate == null) || certificateValidFrom.before(statusEndDate))) {

				found = true;
			}
		}

		constraint.setValue(found);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.CTS_IIDOCWVPOTS_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the TSL status of the signing certificate.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param certificateXmlDom
	 * @return
	 */
	private boolean checkSigningCertificateTSLStatusConstraint(final Conclusion conclusion, final CertificateWrapper certificate) {

		final String trustedSource = certificate.getLastChainCertificateSource();
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		final Constraint constraint = constraintData.getSigningCertificateTSLStatusConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.CTS_WITSS);

		List<XmlTrustedServiceProviderType> tspList = diagnosticData.getCertificateTSPService(certificate);
		boolean acceptableStatus = false;
		String status = StringUtils.EMPTY;
		for (final XmlTrustedServiceProviderType trustedServiceProvider : tspList) {
			status = trustedServiceProvider == null ? "" : trustedServiceProvider.getStatus();
			acceptableStatus = TSLConstant.SERVICE_STATUS_UNDERSUPERVISION.equals(status) || TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION.equals(status)
					|| TSLConstant.SERVICE_STATUS_ACCREDITED.equals(status) || TSLConstant.SERVICE_STATUS_UNDERSUPERVISION_119612.equals(status)
					|| TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION_119612.equals(status) || TSLConstant.SERVICE_STATUS_ACCREDITED_119612.equals(status);
			if (acceptableStatus) {
				break;
			}
		}

		constraint.setValue(acceptableStatus);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.CTS_WITSS_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setAttribute(AttributeValue.TRUSTED_SERVICE_STATUS, status);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the TSL status of the signing certificate.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param certificateXmlDom
	 * @return
	 */
	private boolean checkSigningCertificateTSLStatusAndValidityConstraint(final Conclusion conclusion, final CertificateWrapper certificate) {
		final String trustedSource = certificate.getLastChainCertificateSource();
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		final Constraint constraint = constraintData.getSigningCertificateTSLStatusAndValidityConstraint(contextName);
		if (constraint == null) {
			return true;
		}

		constraint.create(validationDataXmlNode, MessageTag.CTS_ITACBT);

		final Date certificateValidFrom = certificate.getNotBefore();

		final List<XmlTrustedServiceProviderType> tspList = diagnosticData.getCertificateTSPService(certificate);
		boolean found = false;
		for (final XmlTrustedServiceProviderType trustedServiceProvider : tspList) {

			final String serviceTypeIdentifier = trustedServiceProvider.getTSPServiceType();
			if (!TSLConstant.CA_QC.equals(serviceTypeIdentifier)) {
				continue;
			}
			final Date statusStartDate = trustedServiceProvider.getStartDate();
			final Date statusEndDate = trustedServiceProvider.getEndDate();
			if (certificateValidFrom.after(statusStartDate) && ((statusEndDate == null) || certificateValidFrom.before(statusEndDate))) {

				final String status = trustedServiceProvider.getStatus();
				found = TSLConstant.SERVICE_STATUS_UNDERSUPERVISION.equals(status) || TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION.equals(status)
						|| TSLConstant.SERVICE_STATUS_ACCREDITED.equals(status) || TSLConstant.SERVICE_STATUS_UNDERSUPERVISION_119612.equals(status)
						|| TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION_119612.equals(status) || TSLConstant.SERVICE_STATUS_ACCREDITED_119612.equals(status);
				if (found) {
					break;
				}
			}
		}

		constraint.setValue(found);
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.TRY_LATER, MessageTag.CTS_ITACBT_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificate.getId());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the intermediate certificate is revoked.
	 * e) If the certificate path validation returns a failure indication because an intermediate CA has been
	 * determined to be revoked, set the current status to INDETERMINATE/REVOKED_CA_NO_POE and go to step 2.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param certificateId
	 * @param revocationStatus
	 * @param revocationReason
	 * @param revocationDatetime
	 * @return false if the check failed and the process should stop, true otherwise.
	 * @param subContext
	 */
	private boolean checkIntermediateCertificateRevokedConstraint(final Conclusion conclusion, final String certificateId, final RevocationWrapper revocation, String subContext) {

		final Constraint constraint = constraintData.getIntermediateCertificateRevokedConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_IICR, certificateId);
		final boolean revoked = !revocation.isStatus();
		constraint.setValue(String.valueOf(revoked));
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.REVOKED_CA_NO_POE, MessageTag.BBB_XCV_IICR_ANS);
		constraint.setAttribute(AttributeValue.CERTIFICATE_ID, certificateId);
		if (revocation.getDateTime() != null) {
			constraint.setAttribute(AttributeName.REVOCATION_TIME, revocation.getDateTime());
		}
		if (StringUtils.isNotBlank(revocation.getReason())) {
			constraint.setAttribute(AttributeName.REVOCATION_REASON, revocation.getReason());
		}
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * 4) Apply the Chain Constraints to the chain. Certificate meta-data shall be taken into account when checking
	 * these constraints against the chain. If the chain does not match these constraints, set the current status to
	 * INVALID/CHAIN_CONSTRAINTS_FAILURE and go to step 2.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 */
	private boolean checkChainConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getChainConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_ACCM);
		// TODO: (Bob: 2014 Mar 09) --> DSS does not check these constraints
		constraint.setValue("TO BE IMPLEMENTED");
		constraint.setIndications(Indication.INVALID, SubIndication.CHAIN_CONSTRAINTS_FAILURE, MessageTag.EMPTY);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Mandates the signer's certificate used in validating the signature to be a qualified certificate as defined
	 * in Directive 1999/93/EC [9]. This status can be derived from:
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param qualifiedCertificate
	 *            indicates if the signing certificate is qualified.
	 */
	protected boolean checkSigningCertificateQualificationConstraint(final Conclusion conclusion, final boolean qualifiedCertificate) {

		final Constraint constraint = constraintData.getSigningCertificateQualificationConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_CMDCIQC);
		constraint.setValue(String.valueOf(qualifiedCertificate));
		constraint.setIndications(Indication.INVALID, SubIndication.CHAIN_CONSTRAINTS_FAILURE, MessageTag.BBB_XCV_CMDCIQC_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Mandates the end user certificate used in validating the signature to be supported by a secure signature
	 * creation device (SSCD) as defined in Directive 1999/93/EC [9].
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param supportedBySSCD
	 *            indicates if the signing certificate is qualified.
	 */
	protected boolean checkSigningCertificateSupportedBySSCDConstraint(final Conclusion conclusion, final boolean supportedBySSCD) {

		final Constraint constraint = constraintData.getSigningCertificateSupportedBySSCDConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_CMDCISSCD);
		constraint.setValue(String.valueOf(supportedBySSCD));
		constraint.setIndications(Indication.INVALID, SubIndication.CHAIN_CONSTRAINTS_FAILURE, MessageTag.BBB_XCV_CMDCISSCD_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Mandates the signer's certificate used in validating the signature to be issued by a certificate authority
	 * issuing certificate as having been issued to a legal person.
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param issuedToLegalPerson
	 *            indicates if the signing certificate is qualified.
	 */
	protected boolean checkSigningCertificateIssuedToLegalPersonConstraint(final Conclusion conclusion, final boolean issuedToLegalPerson) {

		final Constraint constraint = constraintData.getSigningCertificateIssuedToLegalPersonConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.BBB_XCV_CMDCIITLP);
		constraint.setValue(String.valueOf(issuedToLegalPerson));
		constraint.setIndications(Indication.INVALID, SubIndication.CHAIN_CONSTRAINTS_FAILURE, MessageTag.BBB_XCV_CMDCIITLP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: main signature cryptographic verification
	 *
	 * @param conclusion
	 *            the conclusion to use to add the result of the check.
	 * @param context
	 * @param subContext
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkCertificateCryptographicConstraint(final Conclusion conclusion, final TokenProxy token, String context, String subContext) {
		if (token == null) {
			return true;
		}
		final SignatureCryptographicConstraint constraint = constraintData.getSignatureCryptographicConstraint(context, subContext);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, MessageTag.ASCCM);
		constraint.setCurrentTime(currentTime);
		constraint.setEncryptionAlgorithm(token.getEncryptionAlgoUsedToSignThisToken());
		constraint.setDigestAlgorithm(token.getDigestAlgoUsedToSignThisToken());
		constraint.setKeyLength(token.getKeyLengthUsedToSignThisToken());
		constraint.setIndications(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, MessageTag.EMPTY);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}
}
