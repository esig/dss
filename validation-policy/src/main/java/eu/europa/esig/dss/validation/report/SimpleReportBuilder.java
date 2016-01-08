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
package eu.europa.esig.dss.validation.report;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScopes;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.jaxb.simplereport.XmlPolicy;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.CertificateQualification;
import eu.europa.esig.dss.validation.policy.ProcessParameters;
import eu.europa.esig.dss.validation.policy.SignatureQualification;
import eu.europa.esig.dss.validation.policy.SignatureType;
import eu.europa.esig.dss.validation.policy.TLQualification;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder {

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
	 * @param params
	 *            validation process parameters
	 * @return the object representing {@code SimpleReport}
	 */
	public eu.europa.esig.dss.jaxb.simplereport.SimpleReport build(final ProcessParameters params) {

		SimpleReport simpleReport = new SimpleReport();

		addPolicyNode(simpleReport);
		addValidationTime(params, simpleReport);
		addDocumentName(simpleReport);
		addSignatures(params, simpleReport);
		addStatistics(simpleReport);

		return simpleReport;
	}

	private void addPolicyNode(final SimpleReport report) {
		XmlPolicy policy = new XmlPolicy();
		policy.setPolicyName(constraintData.getPolicyName());
		policy.setPolicyDescription(constraintData.getPolicyDescription());
		report.setPolicy(policy);
	}

	private void addValidationTime(final ProcessParameters params, final SimpleReport report) {
		report.setValidationTime(params.getCurrentTime());
	}

	private void addDocumentName(final SimpleReport report) {
		report.setDocumentName(diagnosticData.getDocumentName());
	}

	private void addSignatures(final ProcessParameters params, final SimpleReport simpleReport) throws DSSException {
		validSignatureCount = 0;
		totalSignatureCount = 0;
		final List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (final SignatureWrapper signature : signatures) {
			addSignature(params, simpleReport, signature);
		}
	}

	private void addStatistics(SimpleReport simpleReport) {
		simpleReport.setValidSignaturesCount(validSignatureCount);
		simpleReport.setSignaturesCount(totalSignatureCount);
	}

	/**
	 * @param params
	 *            validation process parameters
	 * @param simpleReport
	 * @param signature
	 *            the diagnosticSignature element in the diagnostic data
	 * @throws DSSException
	 */
	private void addSignature(final ProcessParameters params, final SimpleReport simpleReport, final SignatureWrapper signature) throws DSSException {

		totalSignatureCount++;

		String signatureId = signature.getId();
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setId(signatureId);

		addCounterSignature(signature, xmlSignature);
		addSigningTime(signature, xmlSignature);
		addSignatureFormat(signature, xmlSignature);
		addSignedBy(signature, xmlSignature);

		XmlDom bvData = params.getBvData();
		final XmlDom basicValidationConclusion = bvData.getElement("/BasicValidationData/Signature[@Id='%s']/Conclusion", signatureId);
		final XmlDom ltvDom = params.getLtvData();
		final XmlDom ltvConclusion = ltvDom.getElement("/LongTermValidationData/Signature[@Id='%s']/Conclusion", signatureId);
		final Indication ltvIndication = Indication.valueOf(ltvConclusion.getValue("./Indication/text()"));
		final SubIndication ltvSubIndication = SubIndication.forName(ltvConclusion.getValue("./SubIndication/text()"));
		final List<XmlDom> ltvInfoList = ltvConclusion.getElements("./Info");

		Indication indication = ltvIndication;
		SubIndication subIndication = ltvSubIndication;
		List<XmlDom> infoList = new ArrayList<XmlDom>();
		infoList.addAll(ltvInfoList);

		final List<XmlDom> basicValidationInfoList = basicValidationConclusion.getElements("./Info");
		final List<XmlDom> basicValidationWarningList = basicValidationConclusion.getElements("./Warning");
		final List<XmlDom> basicValidationErrorList = basicValidationConclusion.getElements("./Error");

		final boolean noTimestamp = Indication.INDETERMINATE.equals(ltvIndication) && SubIndication.NO_TIMESTAMP.equals(ltvSubIndication);
		if (noTimestamp) {

			final Indication basicValidationConclusionIndication = Indication.valueOf(basicValidationConclusion.getValue("./Indication/text()"));
			final SubIndication basicValidationConclusionSubIndication = SubIndication.forName(basicValidationConclusion.getValue("./SubIndication/text()"));
			indication = basicValidationConclusionIndication;
			subIndication = basicValidationConclusionSubIndication;
			infoList = basicValidationInfoList;
			if (!Indication.VALID.equals(basicValidationConclusionIndication)) {

				if (noTimestamp) {
					xmlSignature.getWarnings().add(MessageTag.LABEL_TINTWS.getMessage());
				} else {
					xmlSignature.getWarnings().add(MessageTag.LABEL_TINVTWS.getMessage());
					for (XmlDom xmlDom : ltvInfoList) {
						xmlSignature.getInfos().add(xmlDom.getText());
					}
				}
			}
		}
		xmlSignature.setIndication(indication);
		if (Indication.VALID.equals(indication)) {
			validSignatureCount++;
		}
		if (subIndication != null) {
			xmlSignature.setSubIndication(subIndication);
		}
		if (basicValidationConclusion != null) {
			String errorMessage = signature.getErrorMessage();
			if (StringUtils.isNotEmpty(errorMessage)) {
				xmlSignature.getInfos().add(StringEscapeUtils.escapeXml(errorMessage));
			}
		}
		if (!Indication.VALID.equals(ltvIndication)) {

			addBasicInfo(xmlSignature, basicValidationErrorList);
		}
		addBasicInfo(xmlSignature, basicValidationWarningList);
		addBasicInfo(xmlSignature, infoList);

		addSignatureProfile(signature, xmlSignature);

		final XmlSignatureScopes signatureScopes = signature.getSignatureScopes();
		addSignatureScope(xmlSignature, signatureScopes);

		simpleReport.getSignatures().add(xmlSignature);
	}

	private void addCounterSignature(SignatureWrapper signature, XmlSignature xmlSignature) {
		if (AttributeValue.COUNTERSIGNATURE.equals(signature.getType())) {
			xmlSignature.setType(AttributeValue.COUNTERSIGNATURE);
			xmlSignature.setParentId(signature.getParentId());
		}
	}

	private void addSignatureScope(final XmlSignature signatureNode, final XmlSignatureScopes signatureScopes) {
		if (signatureScopes != null) {
			//TODO	signatureNode.addChild(signatureScopes);
		}
	}

	private void addBasicInfo(final XmlSignature xmlSignature, final List<XmlDom> basicValidationErrorList) {
		for (final XmlDom error : basicValidationErrorList) {
			xmlSignature.getErrors().add(error.getText());
		}
	}

	private void addSigningTime(final SignatureWrapper diagnosticSignature, final XmlSignature xmlSignature) {
		xmlSignature.setSigningTime(diagnosticSignature.getDateTime());
	}

	private void addSignatureFormat(final SignatureWrapper diagnosticSignature, final XmlSignature xmlSignature) {
		xmlSignature.setSignatureFormat(diagnosticSignature.getSignatureFormat());
	}

	private void addSignedBy(final SignatureWrapper diagnosticSignature, final XmlSignature xmlSignature) {
		String unknown = "?";
		String signedBy = unknown;
		String certificateId = diagnosticSignature.getSigningCertificateId();
		if (StringUtils.isNotEmpty(certificateId)) {
			signedBy = diagnosticData.getUsedCertificateById(certificateId).getCommonName();
			if(signedBy.equals(StringUtils.EMPTY)) {
				signedBy = diagnosticData.getUsedCertificateById(certificateId).getGivenName();
				if(signedBy.equals(StringUtils.EMPTY)) {
					signedBy = diagnosticData.getUsedCertificateById(certificateId).getSurname();
					if(signedBy.equals(StringUtils.EMPTY)) {
						signedBy = diagnosticData.getUsedCertificateById(certificateId).getPseudo();
						if(signedBy.equals(StringUtils.EMPTY)) {
							signedBy = unknown;
						}
					}
				}
			} 
		}
		xmlSignature.setSignedBy(signedBy);
	}

	/**
	 * Here we determine the type of the signature.
	 */
	private void addSignatureProfile(SignatureWrapper signature, XmlSignature xmlSignature) {
		SignatureType signatureType = SignatureType.NA;
		String certificateId = signature.getSigningCertificateId();
		if (certificateId != null) {
			signatureType = getSignatureType(certificateId);
		}
		xmlSignature.setSignatureLevel(signatureType.name());
	}

	/**
	 * This method returns the type of the qualification of the signature (signing certificate).
	 *
	 * @param signCert
	 * @return
	 */
	private SignatureType getSignatureType(final String certificateId) {

		CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(certificateId);
		final CertificateQualification certQualification = new CertificateQualification();
		certQualification.setQcp(certificate.isCertificateQCP());
		certQualification.setQcpp(certificate.isCertificateQCPPlus());
		certQualification.setQcc(certificate.isCertificateQCC());
		certQualification.setQcsscd(certificate.isCertificateQCSSCD());

		final TLQualification trustedListQualification = new TLQualification();

		final String caqc = certificate.getCertificateTSPServiceType();

		final List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();

		trustedListQualification.setCaqc(TSLConstant.CA_QC.equals(caqc));
		trustedListQualification.setQcCNoSSCD(isQcNoSSCD(qualifiers));
		trustedListQualification.setQcForLegalPerson(isQcForLegalPerson(qualifiers));
		trustedListQualification.setQcSSCDAsInCert(isQcSscdStatusAsInCert(qualifiers));
		trustedListQualification.setQcWithSSCD(isQcWithSSCD(qualifiers));

		final SignatureType signatureType = SignatureQualification.getSignatureType(certQualification, trustedListQualification);
		return signatureType;
	}

	private boolean isQcNoSSCD(final List<String> qualifiers) {
		return qualifiers.contains(TSLConstant.QC_NO_SSCD) || qualifiers.contains(TSLConstant.QC_NO_SSCD_119612);
	}

	private boolean isQcForLegalPerson(final List<String> qualifiers) {
		return qualifiers.contains(TSLConstant.QC_FOR_LEGAL_PERSON) || qualifiers.contains(TSLConstant.QC_FOR_LEGAL_PERSON_119612);
	}

	private boolean isQcSscdStatusAsInCert(final List<String> qualifiers) {
		return qualifiers.contains(TSLConstant.QCSSCD_STATUS_AS_IN_CERT) || qualifiers.contains(TSLConstant.QCSSCD_STATUS_AS_IN_CERT_119612);
	}

	private boolean isQcWithSSCD(final List<String> qualifiers) {
		return qualifiers.contains(TSLConstant.QC_WITH_SSCD) || qualifiers.contains(TSLConstant.QC_WITH_SSCD_119612);
	}

}
