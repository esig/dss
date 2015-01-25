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
package eu.europa.ec.markt.dss.validation102853.report;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.apache.commons.lang.StringEscapeUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.X509Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateQualification;
import eu.europa.ec.markt.dss.validation102853.SignatureQualification;
import eu.europa.ec.markt.dss.validation102853.SignatureType;
import eu.europa.ec.markt.dss.validation102853.TLQualification;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.processes.dss.InvolvedServiceInfo;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.LABEL_TINTWS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.LABEL_TINVTWS;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class SimpleReportBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SimpleReportBuilder.class);

	private final ValidationPolicy constraintData;
	private final DiagnosticData diagnosticData;

	private int totalSignatureCount = 0;
	private int validSignatureCount = 0;

	public SimpleReportBuilder(final ValidationPolicy constraintData, final DiagnosticData diagnosticData) {

		this.constraintData = constraintData;
		this.diagnosticData = diagnosticData;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @param params validation process parameters
	 * @return the object representing {@code SimpleReport}
	 */
	public SimpleReport build(final ProcessParameters params) {

		final XmlNode simpleReport = new XmlNode(NodeName.SIMPLE_REPORT);
		simpleReport.setNameSpace(XmlDom.NAMESPACE);

		try {

			addPolicyNode(simpleReport);

			addValidationTime(params, simpleReport);

			addDocumentName(simpleReport);

			addSignatures(params, simpleReport);

			addStatistics(simpleReport);
		} catch (Exception e) {

			if (!"WAS TREATED".equals(e.getMessage())) {

				notifyException(simpleReport, e);
			}
		}
		final Document reportDocument = simpleReport.toDocument();
		return new SimpleReport(reportDocument);
	}

	private void addPolicyNode(final XmlNode report) {

		final XmlNode policyNode = report.addChild(NodeName.POLICY);
		final String policyName = constraintData.getPolicyName();
		final String policyDescription = constraintData.getPolicyDescription();
		policyNode.addChild(NodeName.POLICY_NAME, policyName);
		policyNode.addChild(NodeName.POLICY_DESCRIPTION, policyDescription);
	}

	private void addValidationTime(final ProcessParameters params, final XmlNode report) {

		final Date validationTime = params.getCurrentTime();
		report.addChild(NodeName.VALIDATION_TIME, DSSUtils.formatDate(validationTime));
	}

	private void addDocumentName(final XmlNode report) {

		final String documentName = diagnosticData.getValue("/DiagnosticData/DocumentName/text()");
		report.addChild(NodeName.DOCUMENT_NAME, documentName);
	}

	private void addSignatures(final ProcessParameters params, final XmlNode simpleReport) throws DSSException {

		final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");
		validSignatureCount = 0;
		totalSignatureCount = 0;
		for (final XmlDom signatureXmlDom : signatures) {

			addSignature(params, simpleReport, signatureXmlDom);
		}
	}

	private void addStatistics(XmlNode report) {

		report.addChild(NodeName.VALID_SIGNATURES_COUNT, Integer.toString(validSignatureCount));
		report.addChild(NodeName.SIGNATURES_COUNT, Integer.toString(totalSignatureCount));
	}

	/**
	 * @param params              validation process parameters
	 * @param simpleReport
	 * @param diagnosticSignature the diagnosticSignature element in the diagnostic data
	 * @throws DSSException
	 */
	private void addSignature(final ProcessParameters params, final XmlNode simpleReport, final XmlDom diagnosticSignature) throws DSSException {

		totalSignatureCount++;

		final XmlNode signatureNode = simpleReport.addChild(NodeName.SIGNATURE);

		final String signatureId = diagnosticSignature.getValue("./@Id");
		signatureNode.setAttribute(AttributeName.ID, signatureId);

		final String type = diagnosticSignature.getValue("./@Type");
		addCounterSignature(diagnosticSignature, signatureNode, type);
		try {

			addSigningTime(diagnosticSignature, signatureNode);
			addSignatureFormat(diagnosticSignature, signatureNode);

			final String signCertId = diagnosticSignature.getValue("./SigningCertificate/@Id");
			final XmlDom signCert = params.getCertificate(signCertId);

			addSignedBy(signatureNode, signCert);

			XmlDom bvData = params.getBvData();
			final XmlDom basicValidationConclusion = bvData.getElement("/BasicValidationData/Signature[@Id='%s']/Conclusion", signatureId);
			final XmlDom ltvDom = params.getLtvData();
			final XmlDom ltvConclusion = ltvDom.getElement("/LongTermValidationData/Signature[@Id='%s']/Conclusion", signatureId);
			final String ltvIndication = ltvConclusion.getValue("./Indication/text()");
			final String ltvSubIndication = ltvConclusion.getValue("./SubIndication/text()");
			final List<XmlDom> ltvInfoList = ltvConclusion.getElements("./Info");

			String indication = ltvIndication;
			String subIndication = ltvSubIndication;
			List<XmlDom> infoList = new ArrayList<XmlDom>();
			infoList.addAll(ltvInfoList);

			final List<XmlDom> basicValidationInfoList = basicValidationConclusion.getElements("./Info");
			final List<XmlDom> basicValidationWarningList = basicValidationConclusion.getElements("./Warning");
			final List<XmlDom> basicValidationErrorList = basicValidationConclusion.getElements("./Error");

			final boolean noTimestamp = Indication.INDETERMINATE.equals(ltvIndication) && SubIndication.NO_TIMESTAMP.equals(ltvSubIndication);
			final boolean noValidTimestamp = Indication.INDETERMINATE.equals(ltvIndication) && SubIndication.NO_VALID_TIMESTAMP.equals(ltvSubIndication);
			if (noTimestamp || noValidTimestamp) {

				final String basicValidationConclusionIndication = basicValidationConclusion.getValue("./Indication/text()");
				final String basicValidationConclusionSubIndication = basicValidationConclusion.getValue("./SubIndication/text()");
				indication = basicValidationConclusionIndication;
				subIndication = basicValidationConclusionSubIndication;
				infoList = basicValidationInfoList;
				if (!Indication.VALID.equals(basicValidationConclusionIndication)) {

					if (noTimestamp) {

						final XmlNode xmlNode = new XmlNode(NodeName.WARNING, LABEL_TINTWS, null);
						final XmlDom xmlDom = xmlNode.toXmlDom();
						infoList.add(xmlDom);
					} else {

						final XmlNode xmlNode = new XmlNode(NodeName.WARNING, LABEL_TINVTWS, null);
						final XmlDom xmlDom = xmlNode.toXmlDom();
						infoList.add(xmlDom);
						infoList.addAll(ltvInfoList);
					}
				}
			}
			signatureNode.addChild(NodeName.INDICATION, indication);
			if (Indication.VALID.equals(indication)) {
				validSignatureCount++;
			}
			if (!subIndication.isEmpty()) {

				signatureNode.addChild(NodeName.SUB_INDICATION, subIndication);
			}
			if (basicValidationConclusion != null) {

				final List<XmlDom> errorMessages = diagnosticSignature.getElements("./ErrorMessage");
				for (XmlDom errorDom : errorMessages) {

					String errorMessage = errorDom.getText();
					errorMessage = StringEscapeUtils.escapeXml(errorMessage);
					final XmlNode xmlNode = new XmlNode(NodeName.INFO, errorMessage);
					final XmlDom xmlDom = xmlNode.toXmlDom();
					infoList.add(xmlDom);
				}
			}
			if (!Indication.VALID.equals(ltvIndication)) {

				addBasicInfo(signatureNode, basicValidationErrorList);
			}
			addBasicInfo(signatureNode, basicValidationWarningList);
			addBasicInfo(signatureNode, infoList);

			addSignatureProfile(signatureNode, signCert);

			final XmlDom signatureScopes = diagnosticSignature.getElement("./SignatureScopes");
			addSignatureScope(signatureNode, signatureScopes);
		} catch (Exception e) {

			notifyException(signatureNode, e);
			throw new DSSException("WAS TREATED", e);
		}
	}

	private void addCounterSignature(XmlDom diagnosticSignature, XmlNode signatureNode, String type) {
		if (AttributeValue.COUNTERSIGNATURE.equals(type)) {

			signatureNode.setAttribute(AttributeName.TYPE, AttributeValue.COUNTERSIGNATURE);
			final String parentId = diagnosticSignature.getValue("./ParentId/text()");
			signatureNode.setAttribute(AttributeName.PARENT_ID, parentId);
		}
	}

	private void addSignatureScope(final XmlNode signatureNode, final XmlDom signatureScopes) {
		if (signatureScopes != null) {
			signatureNode.addChild(signatureScopes);
		}
	}

	private void addBasicInfo(final XmlNode signatureNode, final List<XmlDom> basicValidationErrorList) {
		for (final XmlDom error : basicValidationErrorList) {

			signatureNode.addChild(error);
		}
	}

	private void addSigningTime(final XmlDom diagnosticSignature, final XmlNode signatureNode) {
		signatureNode.addChild(NodeName.SIGNING_TIME, diagnosticSignature.getValue("./DateTime/text()"));
	}

	private void addSignatureFormat(final XmlDom diagnosticSignature, final XmlNode signatureNode) {
		signatureNode.setAttribute(NodeName.SIGNATURE_FORMAT, diagnosticSignature.getValue("./SignatureFormat/text()"));
	}

	private void addSignedBy(final XmlNode signatureNode, final XmlDom signCert) {

		String signedBy = "?";
		if (signCert != null) {

			final String dn = signCert.getValue("./SubjectDistinguishedName[@Format='RFC2253']/text()");
			final X509Principal principal = new X509Principal(dn);
			final Vector<?> values = principal.getValues(new ASN1ObjectIdentifier("2.5.4.3"));
			if (values != null && values.size() > 0) {

				final String string = (String) values.get(0);
				if (DSSUtils.isNotBlank(string)) {
					signedBy = DSSUtils.replaceStrStr(string, "&", "&amp;");
				}
				if (DSSUtils.isEmpty(signedBy)) {
					signedBy = DSSUtils.replaceStrStr(dn, "&", "&amp;");
				}
			}
		}
		signatureNode.addChild(NodeName.SIGNED_BY, signedBy);
	}

	private void addSignatureProfile(XmlNode signatureNode, XmlDom signCert) {
		/**
		 * Here we determine the type of the signature.
		 */
		SignatureType signatureType = SignatureType.NA;
		if (signCert != null) {

			signatureType = getSignatureType(signCert);
		}
		signatureNode.addChild(NodeName.SIGNATURE_LEVEL, signatureType.name());
	}

	/**
	 * This method returns the type of the qualification of the signature (signing certificate).
	 *
	 * @param signCert
	 * @return
	 */
	private SignatureType getSignatureType(final XmlDom signCert) {

		final CertificateQualification certQualification = new CertificateQualification();
		certQualification.setQcp(signCert.getBoolValue("./QCStatement/QCP/text()"));
		certQualification.setQcpp(signCert.getBoolValue("./QCStatement/QCPPlus/text()"));
		certQualification.setQcc(signCert.getBoolValue("./QCStatement/QCC/text()"));
		certQualification.setQcsscd(signCert.getBoolValue("./QCStatement/QCSSCD/text()"));

		final TLQualification trustedListQualification = new TLQualification();

		final String caqc = InvolvedServiceInfo.getServiceTypeIdentifier(signCert);

		final List<String> qualifiers = InvolvedServiceInfo.getQualifiers(signCert);

		trustedListQualification.setCaqc(TSLConstant.CA_QC.equals(caqc));
		trustedListQualification.setQcCNoSSCD(InvolvedServiceInfo.isQC_NO_SSCD(qualifiers));
		trustedListQualification.setQcForLegalPerson(InvolvedServiceInfo.isQC_FOR_LEGAL_PERSON(qualifiers));
		trustedListQualification.setQcSSCDAsInCert(InvolvedServiceInfo.isQCSSCD_STATUS_AS_IN_CERT(qualifiers));
		trustedListQualification.setQcWithSSCD(qualifiers.contains(TSLConstant.QC_WITH_SSCD) || qualifiers.contains(TSLConstant.QC_WITH_SSCD_119612));

		final SignatureType signatureType = SignatureQualification.getSignatureType(certQualification, trustedListQualification);
		return signatureType;
	}

	/**
	 * @param signatureNode
	 * @param exception
	 */
	private static void notifyException(final XmlNode signatureNode, final Exception exception) {

		LOG.error(exception.getMessage(), exception);

		signatureNode.removeChild(NodeName.INDICATION);
		signatureNode.removeChild(NodeName.SUB_INDICATION);

		signatureNode.addChild(NodeName.INDICATION, Indication.INDETERMINATE);
		signatureNode.addChild(NodeName.SUB_INDICATION, SubIndication.UNEXPECTED_ERROR);

		final String message = DSSUtils.getSummaryMessage(exception, SimpleReportBuilder.class);
		signatureNode.addChild(NodeName.INFO, message);
	}
}
