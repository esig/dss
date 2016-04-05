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
package eu.europa.esig.dss.validation.executor;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScopeType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScopes;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.jaxb.simplereport.XmlPolicy;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureScope;
import eu.europa.esig.dss.validation.AttributeValue;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.CertificateQualification;
import eu.europa.esig.dss.validation.policy.SignatureQualification;
import eu.europa.esig.dss.validation.policy.TLQualification;
import eu.europa.esig.dss.validation.policy.TSLConstant;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.SignatureType;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder {

	private static final Logger logger = LoggerFactory.getLogger(SimpleReportBuilder.class);

	private final Date currentTime;
	private final ValidationPolicy policy;
	private final DiagnosticData diagnosticData;
	private final ValidationLevel validationLevel;
	private final DetailedReport detailedReport;

	private int totalSignatureCount = 0;
	private int validSignatureCount = 0;

	public SimpleReportBuilder(Date currentTime, ValidationPolicy policy, DiagnosticData diagnosticData, ValidationLevel validationLevel,
			DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
		this.validationLevel = validationLevel;
		this.detailedReport = detailedReport;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @param params
	 *            validation process parameters
	 * @return the object representing {@code SimpleReport}
	 */
	public eu.europa.esig.dss.jaxb.simplereport.SimpleReport build() {

		SimpleReport simpleReport = new SimpleReport();

		addPolicyNode(simpleReport);
		addValidationTime(simpleReport);
		addDocumentName(simpleReport);
		addSignatures(simpleReport);
		addStatistics(simpleReport);

		return simpleReport;
	}

	private void addPolicyNode(SimpleReport report) {
		XmlPolicy xmlpolicy = new XmlPolicy();
		xmlpolicy.setPolicyName(policy.getPolicyName());
		xmlpolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setPolicy(xmlpolicy);
	}

	private void addValidationTime(SimpleReport report) {
		report.setValidationTime(currentTime);
	}

	private void addDocumentName(SimpleReport report) {
		report.setDocumentName(diagnosticData.getDocumentName());
	}

	private void addSignatures(SimpleReport simpleReport) throws DSSException {
		validSignatureCount = 0;
		totalSignatureCount = 0;
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper signature : signatures) {
			addSignature(simpleReport, signature);
		}
	}

	private void addStatistics(SimpleReport simpleReport) {
		simpleReport.setValidSignaturesCount(validSignatureCount);
		simpleReport.setSignaturesCount(totalSignatureCount);
	}

	/**
	 * @param simpleReport
	 * @param signature
	 *            the diagnosticSignature element in the diagnostic data
	 * @throws DSSException
	 */
	private void addSignature(SimpleReport simpleReport, SignatureWrapper signature) throws DSSException {

		totalSignatureCount++;

		String signatureId = signature.getId();
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setId(signatureId);

		addCounterSignature(signature, xmlSignature);
		addSignatureScope(signature, xmlSignature);
		addSigningTime(signature, xmlSignature);
		addSignatureFormat(signature, xmlSignature);
		addSignedBy(signature, xmlSignature);

		XmlConstraintsConclusion conclusion = null;
		switch (validationLevel) {
		case BASIC_SIGNATURES:
			conclusion = getBasicSignatureValidationConclusion(signatureId);
			break;
		case TIMESTAMPS:
		case LONG_TERM_DATA:
			conclusion = getLongTermDataValidationConclusion(signatureId);
			break;
		case ARCHIVAL_DATA:
			conclusion = getArchivalValidationConclusion(signatureId);
			break;
		default:
			logger.error("Unsupported validation level : " + validationLevel);
			break;
		}

		Indication indication = conclusion.getConclusion().getIndication();
		SubIndication subIndication = conclusion.getConclusion().getSubIndication();

		List<String> infoList = xmlSignature.getInfos();

		for (XmlConstraint constraint : getAllBBBConstraintsForASignature(xmlSignature)) {
			if (XmlStatus.WARNING.equals(constraint.getStatus())) {
				infoList.add(MessageTag.valueOf(constraint.getName().getNameId() + "_ANS").getMessage());
			}
		}

		xmlSignature.setIndication(indication);
		xmlSignature.setSubIndication(subIndication);
		if (Indication.VALID.equals(indication)) {
			validSignatureCount++;
		}

		addSignatureProfile(signature, xmlSignature);

		simpleReport.getSignature().add(xmlSignature);
	}

	private List<XmlConstraint> getAllBBBConstraintsForASignature(XmlSignature signature) {
		List<XmlConstraint> result = new ArrayList<XmlConstraint>();
		for (XmlBasicBuildingBlocks bbb : detailedReport.getBasicBuildingBlocks()) {
			if (bbb.getId().equals(signature.getId())) { // Check if it's the BBB for the signature
				if (bbb.getCV() != null) {
					result.addAll(bbb.getCV().getConstraint());
				}
				if (bbb.getISC() != null) {
					result.addAll(bbb.getISC().getConstraint());
				}
				if (bbb.getSAV() != null) {
					result.addAll(bbb.getSAV().getConstraint());
				}
				if (bbb.getVCI() != null) {
					result.addAll(bbb.getVCI().getConstraint());
				}
				if (bbb.getXCV() != null) {
					result.addAll(bbb.getXCV().getConstraint());
				}
			}
		}
		return result;
	}

	private XmlConstraintsConclusion getBasicSignatureValidationConclusion(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignature();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (StringUtils.equals(signatureId, xmlSignature.getId())) {
				return xmlSignature.getValidationProcessBasicSignatures();
			}
		}
		return null;
	}

	private XmlConstraintsConclusion getLongTermDataValidationConclusion(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignature();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (StringUtils.equals(signatureId, xmlSignature.getId())) {
				return xmlSignature.getValidationProcessLongTermData();
			}
		}
		return null;
	}

	private XmlConstraintsConclusion getArchivalValidationConclusion(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignature();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (StringUtils.equals(signatureId, xmlSignature.getId())) {
				return xmlSignature.getValidationProcessArchivalData();
			}
		}
		return null;
	}

	private void addCounterSignature(SignatureWrapper signature, XmlSignature xmlSignature) {
		if (AttributeValue.COUNTERSIGNATURE.equals(signature.getType())) {
			xmlSignature.setType(AttributeValue.COUNTERSIGNATURE);
			xmlSignature.setParentId(signature.getParentId());
		}
	}

	private void addSignatureScope(final SignatureWrapper diagnosticSignature, final XmlSignature xmlSignature) {
		XmlSignatureScopes signatureScopes = diagnosticSignature.getSignatureScopes();
		if (signatureScopes != null && CollectionUtils.isNotEmpty(signatureScopes.getSignatureScope())) {
			for (XmlSignatureScopeType scopeType : signatureScopes.getSignatureScope()) {
				XmlSignatureScope scope = new XmlSignatureScope();
				scope.setName(scopeType.getName());
				scope.setScope(scopeType.getScope());
				scope.setValue(scopeType.getValue());
				xmlSignature.getSignatureScope().add(scope);
			}
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
			if (signedBy.equals(StringUtils.EMPTY)) {
				signedBy = diagnosticData.getUsedCertificateById(certificateId).getGivenName();
				if (signedBy.equals(StringUtils.EMPTY)) {
					signedBy = diagnosticData.getUsedCertificateById(certificateId).getSurname();
					if (signedBy.equals(StringUtils.EMPTY)) {
						signedBy = diagnosticData.getUsedCertificateById(certificateId).getPseudo();
						if (signedBy.equals(StringUtils.EMPTY)) {
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
		trustedListQualification.setQcStatement(isQcStatement(qualifiers));

		final SignatureType signatureType = SignatureQualification.getSignatureType(certQualification, trustedListQualification);
		return signatureType;
	}

	private boolean isQcStatement(List<String> qualifiers) {
		return qualifiers.contains(TSLConstant.QC_STATEMENT) || qualifiers.contains(TSLConstant.QC_STATEMENT_119612);
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
