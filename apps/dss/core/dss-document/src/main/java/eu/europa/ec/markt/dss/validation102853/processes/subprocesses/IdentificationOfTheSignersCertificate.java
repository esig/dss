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

package eu.europa.ec.markt.dss.validation102853.processes.subprocesses;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.policy.Constraint;
import eu.europa.ec.markt.dss.validation102853.policy.EtsiValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_AIDNASNE;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_AIDNASNE_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ICDVV;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ICDVV_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISACDP;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISACDP_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISASCP;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISASCP_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISCI;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISCI_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISCS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_ICS_ISCS_ANS;

/**
 * 5.1 Identification of the Signer's Certificate (ISC)
 * <p/>
 * 5.1.1 Description
 * This process consists in identifying the signer's certificate that will be used to validate the signature.
 * 5.1.2 Inputs
 * Table 3: Inputs to the ISC process
 * - Input                Requirement
 * - Signature            Mandatory
 * - Signer's Certificate Optional
 * 5.1.3 Outputs
 * • In case of success, i.e. the signer's certificate can be identified, the output shall be the signer's certificate.
 * • In case of failure, i.e. the signer's certificate cannot be identified, the output shall be the indication INDETERMINATE and the sub indication NO_SIGNER_CERTIFICATE_FOUND.
 * NOTE: If the signature is compliant with the CD 2011/130/EU, this process will never return INDETERMINATE, since the signer's certificate is present in the signature.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class IdentificationOfTheSignersCertificate implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

	/**
	 * The following variables are used only in order to simplify the writing of the rules!
	 */

	/**
	 * See {@link ProcessParameters#getValidationPolicy()}
	 */
	private EtsiValidationPolicy constraintData;

	/**
	 * See {@link ProcessParameters#getDiagnosticData()}
	 */
	private XmlDom diagnosticData;

	/**
	 * // TODO: (Bob: 2014 Mar 12)
	 */
	private String contextName;

	/**
	 * See {@link ProcessParameters#getContextElement()}
	 */
	private XmlDom contextElement;

	/**
	 * This node is used to add the constraint nodes.
	 */
	private XmlNode validationDataXmlNode;

	private void prepareParameters(final ProcessParameters params) {

		this.constraintData = (EtsiValidationPolicy) params.getValidationPolicy();
		this.diagnosticData = params.getDiagnosticData();
		this.contextElement = params.getContextElement();
		isInitialised();
	}

	private void isInitialised() {

		if (constraintData == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
		}
		if (diagnosticData == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
		}
		if (contextElement == null) {
			throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "contextElement"));
		}
	}

	/**
	 * This method prepares the execution of the ISC process.
	 *
	 * @param params validation process parameters
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	public Conclusion run(final ProcessParameters params, final String contextName) {

		this.contextName = contextName;
		prepareParameters(params);

		/**
		 * 5.1 Identification of the signer's certificate (ISC)
		 */
		validationDataXmlNode = new XmlNode(ISC);
		validationDataXmlNode.setNameSpace(XmlDom.NAMESPACE);

		final Conclusion conclusion = process(params);

		conclusion.setValidationData(validationDataXmlNode);
		return conclusion;
	}

	/**
	 * This method implements ISC process.
	 * <p/>
	 * 5.1.4 Processing
	 * The common way to unambiguously identify the signer's certificate is by using a property/attribute of the signature
	 * containing a reference to it, which includes the digest computed over the certificates encoded value. The certificate or a
	 * reference to the certificate can either be found in the signature or it can be obtained using external sources. The signer's
	 * certificate may also be provided by the DA. If the certificate cannot be retrieved, the indication INDETERMINATE will
	 * be the result.
	 * Clauses 5.1.4.1 to 5.1.4.3 provide specific processing details for each AdES signature type (i.e. XAdES, CAdES or
	 * PAdES), once the certificate has been retrieved.
	 *
	 * @param params validation process parameters
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion process(final ProcessParameters params) {

		final Conclusion conclusion = new Conclusion();

		// The signing certificate Id and the signing certificate are reset.
		params.setSigningCertificateId(null);
		params.setSigningCertificate(null);

		final String signingCertificateId = contextElement.getValue("./SigningCertificate/@Id");
		final XmlDom signingCertificateXmlDom = params.getCertificate(signingCertificateId);
		final boolean signingCertificateRecognised = signingCertificateXmlDom != null;
		if (!checkRecognitionConstraint(conclusion, signingCertificateRecognised, signingCertificateId)) {
			return conclusion;
		}
		/**
		 * The signing certificate Id and the signing certificate are saved for further use.
		 */
		params.setSigningCertificateId(signingCertificateId);
		params.setSigningCertificate(signingCertificateXmlDom);

		Constraint constraint = null;
		final String signedElement = contextElement.getValue("./SigningCertificate/Signed/text()");
		if (DSSUtils.isNotEmpty(signedElement)) {

			constraint = constraintData.getSigningCertificateSignedConstraint(contextName);
			if (constraint != null) {
				if (!checkSignedSigningCertificateConstraint(constraint, conclusion, signedElement)) {
					return conclusion;
				}
			}
		}
		if (constraint == null) {

			if (!checkSigningCertificateAttributePresentConstraint(conclusion)) {
				return conclusion;
			}

			if (!checkDigestValuePresentConstraint(conclusion)) {
				return conclusion;
			}

			if (!checkDigestValueMatchConstraint(conclusion)) {
				return conclusion;
			}

			if (!checkIssuerSerialMatchConstraint(conclusion)) {
				return conclusion;
			}
		}
		// This validation process returns VALID
		conclusion.setIndication(VALID);
		return conclusion;
	}

	/**
	 * @param conclusion                   the conclusion to use to add the result of the check.
	 * @param signingCertificateRecognised indicates if the signing certificate was recognised.
	 * @param signingCertificateId
	 * @return false if the check failed and the process should stop, true otherwise.
	 */

	private boolean checkRecognitionConstraint(final Conclusion conclusion, final boolean signingCertificateRecognised, String signingCertificateId) {

		final Constraint constraint = constraintData.getSigningCertificateRecognitionConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, BBB_ICS_ISCI);
		constraint.setValue(signingCertificateRecognised);
		if (DSSUtils.isNotBlank(signingCertificateId) && !signingCertificateId.equals("0")) {
			constraint.setAttribute(CERTIFICATE_ID, signingCertificateId);
		}
		constraint.setIndications(INDETERMINATE, NO_SIGNER_CERTIFICATE_FOUND, BBB_ICS_ISCI_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}


	private boolean checkSignedSigningCertificateConstraint(final Constraint constraint, final Conclusion conclusion, final String signedElement) {

		constraint.create(validationDataXmlNode, BBB_ICS_ISCS);
		final boolean signed = XPathQueryHolder.XMLE_X509CERTIFICATE.equals(signedElement) || XPathQueryHolder.XMLE_X509DATA.equals(signedElement) || XPathQueryHolder.XMLE_KEYINFO
			  .equals(signedElement);
		constraint.setValue(signed);
		constraint.setIndications(INVALID, FORMAT_FAILURE, BBB_ICS_ISCS_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	private boolean checkSigningCertificateAttributePresentConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSigningCertificateAttributePresentConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, BBB_ICS_ISASCP);
		final boolean digestValueMatch = contextElement.getBoolValue("./SigningCertificate/AttributePresent/text()");
		constraint.setValue(digestValueMatch);
		constraint.setIndications(INVALID, FORMAT_FAILURE, BBB_ICS_ISASCP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * This method checks if the digest value of the signing certificate is within the signature
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkDigestValuePresentConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSigningCertificateDigestValuePresentConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, BBB_ICS_ISACDP);
		final boolean digestValueMatch = contextElement.getBoolValue("./SigningCertificate/DigestValuePresent/text()");
		constraint.setValue(digestValueMatch);
		constraint.setIndications(INVALID, FORMAT_FAILURE, BBB_ICS_ISACDP_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * 5.1.4.1 XAdES processing / 5.1.4.2 CAdES processing / 5.1.4.3 PAdES processing<br/>
	 * <br/>
	 * For XAdES:<br/>
	 * The signing certificate shall be checked against all references present in the ds:SigningCertificate property,
	 * if present, since one of these references shall be a reference to the signing certificate [1]. The following
	 * steps shall be performed:<br/>
	 * <br/>
	 * 1) Take the first child of the property and check that the content of ds:DigestValue matches the result of
	 * digesting the signing certificate with the algorithm indicated in ds:DigestMethod. If they do not match, take
	 * the next child and repeat this step until a matching child element has been found or all children of the
	 * element have been checked. If they do match, continue with step 2. If the last element is reached without
	 * finding any match, the validation of this property shall be taken as failed and INVALID/FORMAT_FAILURE is
	 * returned.<br/>
	 * <br/>
	 * For CAdES:<br/>
	 * The signing certificate shall be checked against the references present in one of the following attributes:
	 * ESS-signing-certificate, ESS-signing-certificate-v2 or Other-signing-certificate, since one of these attributes shall
	 * contain a reference to the signing certificate. For doing this, the following tasks shall be performed:
	 * 1) Take the first element of the attribute and check that the content of the field containing the digest value
	 * matches the result of digesting the signing certificate with the algorithm implicitly or explicitly indicated in the
	 * reference attribute. If they match, continue with step 2. Otherwise the validation of this attribute shall be taken
	 * as failed and INVALID/FORMAT_FAILURE is returned.<br/>
	 * <br/>
	 * For PAdES:<br/>
	 * The signing certificate shall be checked against the references present in one of the following attributes:
	 * ESS-signing-certificate or ESS-signing-certificate-v2, since one of these attributes shall contain a reference to the
	 * signing certificate. For doing this, follow the same steps as for CAdES (see clause 5.1.4.2).
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkDigestValueMatchConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSigningCertificateDigestValueMatchConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, BBB_ICS_ICDVV);
		final boolean digestValueMatch = contextElement.getBoolValue("./SigningCertificate/DigestValueMatch/text()");
		constraint.setValue(digestValueMatch);
		constraint.setIndications(INVALID, FORMAT_FAILURE, BBB_ICS_ICDVV_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * 5.1.4.1 XAdES processing / 5.1.4.2 CAdES processing / 5.1.4.3 PAdES processing<br/>
	 * ...<p/>
	 * For XAdES:<br/>
	 * 2) If the ds:KeyInfo contains the ds:X509IssuerSerial element, check that the issuer and the serial
	 * number indicated in that element and IssuerSerial from SigningCertificate are the same. If they do
	 * not match, the validation of this property shall be taken as failed and INDETERMINATE is returned.<br/>
	 * <p/>
	 * For CAdES:<br/>
	 * 2) Compare the details of the issuer's name and the serial number of the certificate with those indicated in the
	 * reference. If any of them does not match, the validation of this attribute shall be taken as failed and
	 * INDETERMINATE is returned.<br/>
	 * <p/>
	 * For PAdES:<br/>
	 * The signing certificate shall be checked against the references present in one of the following attributes:
	 * ESS-signing-certificate or ESS-signing-certificate-v2, since one of these attributes shall contain a reference to the
	 * signing certificate. For doing this, follow the same steps as for CAdES (see clause 5.1.4.2).
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkIssuerSerialMatchConstraint(final Conclusion conclusion) {

		final Constraint constraint = constraintData.getSigningCertificateIssuerSerialMatchConstraint(contextName);
		if (constraint == null) {
			return true;
		}
		constraint.create(validationDataXmlNode, BBB_ICS_AIDNASNE);
		final boolean issuerSerialMatch = contextElement.getBoolValue("./SigningCertificate/IssuerSerialMatch/text()");
		constraint.setValue(issuerSerialMatch);
		constraint.setIndications(INDETERMINATE, NO_SIGNER_CERTIFICATE_FOUND, BBB_ICS_AIDNASNE_ANS);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}
}
