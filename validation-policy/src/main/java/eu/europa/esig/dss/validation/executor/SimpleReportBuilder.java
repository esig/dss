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

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScopeType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScopes;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.jaxb.simplereport.XmlPolicy;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureScope;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AttributeValue;
import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.CertificateQualification;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.policy.SignatureQualification;
import eu.europa.esig.dss.validation.policy.TLQualification;
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

		XmlConstraintsConclusion constraintsConclusion = null;
		switch (validationLevel) {
		case BASIC_SIGNATURES:
			constraintsConclusion = getBasicSignatureValidationConclusion(signatureId);
			break;
		case TIMESTAMPS:
		case LONG_TERM_DATA:
			constraintsConclusion = getLongTermDataValidationConclusion(signatureId);
			break;
		case ARCHIVAL_DATA:
			constraintsConclusion = getArchivalValidationConclusion(signatureId);
			break;
		default:
			logger.error("Unsupported validation level : " + validationLevel);
			break;
		}

		Indication indication = constraintsConclusion.getConclusion().getIndication();
		SubIndication subIndication = constraintsConclusion.getConclusion().getSubIndication();

		List<String> errorList = xmlSignature.getErrors();

		XmlConclusion conclusion = constraintsConclusion.getConclusion();
		List<XmlName> errors = conclusion.getErrors();
		if (Utils.isCollectionNotEmpty(errors)) {
			for (XmlName error : errors) {
				errorList.add(error.getValue());
			}
		}

		// TODO refactor
		xmlSignature.getWarnings().addAll(getWarnings(signatureId));
		xmlSignature.getInfos().addAll(getInfos(signatureId));

		if (Indication.PASSED.equals(indication)) {
			validSignatureCount++;
			xmlSignature.setIndication(Indication.TOTAL_PASSED);
		} else if (Indication.FAILED.equals(indication)) {
			xmlSignature.setIndication(Indication.TOTAL_FAILED);
		} else {
			xmlSignature.setIndication(indication); // INDERTERMINATE
		}
		xmlSignature.setSubIndication(subIndication);

		addSignatureProfile(signature, xmlSignature);

		simpleReport.getSignature().add(xmlSignature);
	}

	private Set<String> getWarnings(String signatureId) {
		Set<String> warns = new HashSet<String>();
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
				collectWarnings(warns, xmlSignature.getValidationProcessBasicSignatures());
				List<XmlValidationProcessTimestamps> validationProcessTimestamps = xmlSignature.getValidationProcessTimestamps();
				if (Utils.isCollectionNotEmpty(validationProcessTimestamps)) {
					for (XmlValidationProcessTimestamps xmlValidationProcessTimestamps : validationProcessTimestamps) {
						collectWarnings(warns, xmlValidationProcessTimestamps);
					}
				}
				collectWarnings(warns, xmlSignature.getValidationProcessLongTermData());
				collectWarnings(warns, xmlSignature.getValidationProcessArchivalData());
			}
		}
		// Collections.sort(warns);
		return warns;
	}

	private void collectWarnings(Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null) {
			if (Utils.isCollectionNotEmpty(constraintConclusion.getConstraint())) {
				for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
					if (Utils.isStringNotEmpty(constraint.getId())) {
						List<XmlBasicBuildingBlocks> basicBuildingBlocks = detailedReport.getBasicBuildingBlocks();
						if (Utils.isCollectionNotEmpty(basicBuildingBlocks)) {
							for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
								if (Utils.areStringsEqual(xmlBasicBuildingBlocks.getId(), constraint.getId())) {
									collectWarnings(result, xmlBasicBuildingBlocks);
								}
							}
						}
					}
					XmlName warning = constraint.getWarning();
					if (warning != null) {
						result.add(warning.getValue());
					}
				}
			}
		}
	}

	private void collectWarnings(Set<String> result, XmlBasicBuildingBlocks bbb) {
		if (bbb != null) {
			collectWarnings(result, bbb.getFC());
			collectWarnings(result, bbb.getISC());
			collectWarnings(result, bbb.getCV());
			collectWarnings(result, bbb.getSAV());
			XmlXCV xcv = bbb.getXCV();
			if (xcv != null) {
				collectWarnings(result, xcv);
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				if (Utils.isCollectionNotEmpty(subXCV)) {
					for (XmlSubXCV xmlSubXCV : subXCV) {
						collectWarnings(result, xmlSubXCV);
					}
				}
			}
			collectWarnings(result, bbb.getVCI());
		}
	}

	private Set<String> getInfos(String signatureId) {
		Set<String> infos = new HashSet<String>();
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
				collectInfos(infos, xmlSignature.getValidationProcessBasicSignatures());
				List<XmlValidationProcessTimestamps> validationProcessTimestamps = xmlSignature.getValidationProcessTimestamps();
				if (Utils.isCollectionNotEmpty(validationProcessTimestamps)) {
					for (XmlValidationProcessTimestamps xmlValidationProcessTimestamps : validationProcessTimestamps) {
						collectInfos(infos, xmlValidationProcessTimestamps);
					}
				}
				collectInfos(infos, xmlSignature.getValidationProcessLongTermData());
				collectInfos(infos, xmlSignature.getValidationProcessArchivalData());
			}
		}
		// Collections.sort(infos);
		return infos;
	}

	private void collectInfos(Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null) {
			if (Utils.isCollectionNotEmpty(constraintConclusion.getConstraint())) {
				for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
					if (Utils.isStringNotEmpty(constraint.getId())) {
						List<XmlBasicBuildingBlocks> basicBuildingBlocks = detailedReport.getBasicBuildingBlocks();
						if (Utils.isCollectionNotEmpty(basicBuildingBlocks)) {
							for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
								if (Utils.areStringsEqual(xmlBasicBuildingBlocks.getId(), constraint.getId())) {
									collectInfos(result, xmlBasicBuildingBlocks);
								}
							}
						}
					}
					XmlName info = constraint.getInfo();
					if (info != null) {
						result.add(info.getValue());
					}
				}
			}
		}
	}

	private void collectInfos(Set<String> result, XmlBasicBuildingBlocks bbb) {
		if (bbb != null) {
			collectInfos(result, bbb.getFC());
			collectInfos(result, bbb.getISC());
			collectInfos(result, bbb.getCV());
			collectInfos(result, bbb.getSAV());
			XmlXCV xcv = bbb.getXCV();
			if (xcv != null) {
				collectInfos(result, xcv);
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				if (Utils.isCollectionNotEmpty(subXCV)) {
					for (XmlSubXCV xmlSubXCV : subXCV) {
						collectInfos(result, xmlSubXCV);
					}
				}
			}
			collectInfos(result, bbb.getVCI());
		}
	}

	private XmlConstraintsConclusion getBasicSignatureValidationConclusion(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
				return xmlSignature.getValidationProcessBasicSignatures();
			}
		}
		return null;
	}

	private XmlConstraintsConclusion getLongTermDataValidationConclusion(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
				return xmlSignature.getValidationProcessLongTermData();
			}
		}
		return null;
	}

	private XmlConstraintsConclusion getArchivalValidationConclusion(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
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
		if (signatureScopes != null && Utils.isCollectionNotEmpty(signatureScopes.getSignatureScope())) {
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
		if (Utils.isStringNotEmpty(certificateId)) {
			signedBy = diagnosticData.getUsedCertificateById(certificateId).getCommonName();
			if (signedBy.equals(Utils.EMPTY_STRING)) {
				signedBy = diagnosticData.getUsedCertificateById(certificateId).getGivenName();
				if (signedBy.equals(Utils.EMPTY_STRING)) {
					signedBy = diagnosticData.getUsedCertificateById(certificateId).getSurname();
					if (signedBy.equals(Utils.EMPTY_STRING)) {
						signedBy = diagnosticData.getUsedCertificateById(certificateId).getPseudo();
						if (signedBy.equals(Utils.EMPTY_STRING)) {
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
		certQualification.setQcp(CertificatePolicyIdentifiers.isQCP(certificate));
		certQualification.setQcpp(CertificatePolicyIdentifiers.isQCPPlus(certificate));
		certQualification.setQcc(QCStatementPolicyIdentifiers.isQCCompliant(certificate));
		certQualification.setQcsscd(QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate));

		final TLQualification trustedListQualification = new TLQualification();

		final String caqc = certificate.getCertificateTSPServiceType();

		final List<String> qualifiers = certificate.getCertificateTSPServiceQualifiers();

		trustedListQualification.setCaqc(ServiceQualification.CA_QC.equals(caqc));
		trustedListQualification.setQcCNoSSCD(ServiceQualification.isQcNoSSCD(qualifiers));
		trustedListQualification.setQcForLegalPerson(ServiceQualification.isQcForLegalPerson(qualifiers));
		trustedListQualification.setQcSSCDAsInCert(ServiceQualification.isQcSscdStatusAsInCert(qualifiers));
		trustedListQualification.setQcWithSSCD(ServiceQualification.isQcWithSSCD(qualifiers));
		trustedListQualification.setQcStatement(ServiceQualification.isQcStatement(qualifiers));

		final SignatureType signatureType = SignatureQualification.getSignatureType(certQualification, trustedListQualification);
		return signatureType;
	}

}
