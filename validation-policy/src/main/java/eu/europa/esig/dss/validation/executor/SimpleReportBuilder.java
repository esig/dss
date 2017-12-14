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
import eu.europa.esig.dss.jaxb.detailedreport.XmlChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationSignatureQualification;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.jaxb.simplereport.XmlCertificate;
import eu.europa.esig.dss.jaxb.simplereport.XmlCertificateChain;
import eu.europa.esig.dss.jaxb.simplereport.XmlPolicy;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureLevel;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureScope;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SimpleReportBuilder.class);

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
	 * @return the object representing {@code SimpleReport}
	 */
	public eu.europa.esig.dss.jaxb.simplereport.SimpleReport build() {

		SimpleReport simpleReport = new SimpleReport();

		addPolicyNode(simpleReport);
		addValidationTime(simpleReport);
		addDocumentName(simpleReport);

		boolean containerInfoPresent = diagnosticData.isContainerInfoPresent();
		if (containerInfoPresent) {
			addContainerType(simpleReport);
		}
		addSignatures(simpleReport, containerInfoPresent);
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

	private void addContainerType(SimpleReport simpleReport) {
		simpleReport.setContainerType(diagnosticData.getContainerType());
	}

	private void addSignatures(SimpleReport simpleReport, boolean container) throws DSSException {
		validSignatureCount = 0;
		totalSignatureCount = 0;
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper signature : signatures) {
			addSignature(simpleReport, signature, container);
		}
	}

	private void addStatistics(SimpleReport simpleReport) {
		simpleReport.setValidSignaturesCount(validSignatureCount);
		simpleReport.setSignaturesCount(totalSignatureCount);
	}

	/**
	 * @param simpleReport
	 *            the JAXB SimpleReport
	 * @param signature
	 *            the signature wrapper
	 * @param container
	 *            true if the current file is a container
	 */
	private void addSignature(SimpleReport simpleReport, SignatureWrapper signature, boolean container) {

		totalSignatureCount++;

		String signatureId = signature.getId();
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setId(signatureId);

		addCounterSignature(signature, xmlSignature);
		addSignatureScope(signature, xmlSignature);
		addSigningTime(signature, xmlSignature);
		addSignatureFormat(signature, xmlSignature);

		xmlSignature.setSignedBy(getSignedBy(signature));

		if (container) {
			xmlSignature.setFilename(signature.getSignatureFilename());
		}

		eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSig = getXmlSignature(signatureId);

		XmlConstraintsConclusion constraintsConclusion = null;
		switch (validationLevel) {
		case BASIC_SIGNATURES:
		case TIMESTAMPS:
			constraintsConclusion = xmlSig.getValidationProcessBasicSignatures();
			break;
		case LONG_TERM_DATA:
			constraintsConclusion = xmlSig.getValidationProcessLongTermData();
			break;
		case ARCHIVAL_DATA:
			constraintsConclusion = xmlSig.getValidationProcessArchivalData();
			break;
		default:
			LOG.error("Unsupported validation level : " + validationLevel);
			break;
		}

		XmlConclusion conclusion = constraintsConclusion.getConclusion();

		Set<String> errorList = new HashSet<String>();
		Set<String> warnList = new HashSet<String>();
		Set<String> infoList = new HashSet<String>();

		XmlValidationSignatureQualification signQualBlock = xmlSig.getValidationSignatureQualification();
		if (signQualBlock != null) {
			List<XmlTLAnalysis> tlAnalysis = detailedReport.getTLAnalysis();
			for (XmlTLAnalysis xmlTLAnalysis : tlAnalysis) {
				collectErrors(errorList, xmlTLAnalysis);
				collectWarnings(warnList, xmlTLAnalysis);
				collectInfos(infoList, xmlTLAnalysis);
			}

			collectErrors(errorList, signQualBlock);
			collectWarnings(warnList, signQualBlock);
			collectInfos(infoList, signQualBlock);

		}

		List<XmlName> errors = conclusion.getErrors();
		if (Utils.isCollectionNotEmpty(errors)) {
			for (XmlName error : errors) {
				errorList.add(error.getValue());
			}
		}

		errorList.addAll(getLinkedErrors(xmlSig));
		warnList.addAll(getWarnings(xmlSig));
		infoList.addAll(getInfos(xmlSig));

		xmlSignature.getErrors().addAll(errorList);
		xmlSignature.getWarnings().addAll(warnList);
		xmlSignature.getInfos().addAll(infoList);

		Indication indication = conclusion.getIndication();
		if (Indication.PASSED.equals(indication)) {
			validSignatureCount++;
			xmlSignature.setIndication(Indication.TOTAL_PASSED);
		} else if (Indication.FAILED.equals(indication)) {
			xmlSignature.setIndication(Indication.TOTAL_FAILED);
		} else {
			xmlSignature.setIndication(indication); // INDERTERMINATE
		}
		xmlSignature.setSubIndication(conclusion.getSubIndication());

		addSignatureProfile(signQualBlock, xmlSignature);

		XmlBasicBuildingBlocks signatureBasicBuildingBlock = getBasicBuildingBlockById(signatureId);
		List<XmlChainItem> chainItems = signatureBasicBuildingBlock.getCertificateChain().getChainItem();
		if (Utils.isCollectionNotEmpty(chainItems)) {
			XmlCertificateChain xmlCertificateChain = new XmlCertificateChain();
			for (XmlChainItem xmlChainItem : chainItems) {
				XmlCertificate certificate = new XmlCertificate();
				certificate.setId(xmlChainItem.getId());
				certificate.setQualifiedName(getReadableCertificateName(xmlChainItem.getId()));
				xmlCertificateChain.getCertificate().add(certificate);
			}
			xmlSignature.setCertificateChain(xmlCertificateChain);
		}

		simpleReport.getSignature().add(xmlSignature);
	}

	private eu.europa.esig.dss.jaxb.detailedreport.XmlSignature getXmlSignature(String signatureId) {
		List<eu.europa.esig.dss.jaxb.detailedreport.XmlSignature> signatures = detailedReport.getSignatures();
		for (eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature : signatures) {
			if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
				return xmlSignature;
			}
		}
		return null;
	}

	private XmlBasicBuildingBlocks getBasicBuildingBlockById(String id) {
		if (id != null) {
			List<XmlBasicBuildingBlocks> basicBuildingBlocks = detailedReport.getBasicBuildingBlocks();
			if (Utils.isCollectionNotEmpty(basicBuildingBlocks)) {
				for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
					if (Utils.areStringsEqual(xmlBasicBuildingBlocks.getId(), id)) {
						return xmlBasicBuildingBlocks;
					}
				}
			}
		}
		return null;
	}

	private Set<String> getLinkedErrors(eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature) {
		Set<String> errors = new HashSet<String>();
		List<XmlValidationProcessTimestamps> validationProcessTimestamps = xmlSignature.getValidationProcessTimestamps();
		if (Utils.isCollectionNotEmpty(validationProcessTimestamps)) {
			for (XmlValidationProcessTimestamps xmlValidationProcessTimestamps : validationProcessTimestamps) {
				collectErrors(errors, xmlValidationProcessTimestamps);
			}
		}
		return errors;
	}

	private Set<String> getWarnings(eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature) {
		Set<String> warns = new HashSet<String>();
		collectWarnings(warns, xmlSignature.getValidationProcessBasicSignatures());
		List<XmlValidationProcessTimestamps> validationProcessTimestamps = xmlSignature.getValidationProcessTimestamps();
		if (Utils.isCollectionNotEmpty(validationProcessTimestamps)) {
			for (XmlValidationProcessTimestamps xmlValidationProcessTimestamps : validationProcessTimestamps) {
				collectWarnings(warns, xmlValidationProcessTimestamps);
			}
		}
		collectWarnings(warns, xmlSignature.getValidationProcessLongTermData());
		collectWarnings(warns, xmlSignature.getValidationProcessArchivalData());
		return warns;
	}

	private void collectWarnings(Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null) {
			if (Utils.isCollectionNotEmpty(constraintConclusion.getConstraint())) {
				for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
					collectWarnings(result, getBasicBuildingBlockById(constraint.getId()));
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

	private void collectErrors(Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null && Utils.isCollectionNotEmpty(constraintConclusion.getConstraint())) {
			for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
				XmlName error = constraint.getError();
				if (error != null) {
					result.add(error.getValue());
				}
			}
		}
	}

	private Set<String> getInfos(eu.europa.esig.dss.jaxb.detailedreport.XmlSignature xmlSignature) {
		Set<String> infos = new HashSet<String>();
		collectInfos(infos, xmlSignature.getValidationProcessBasicSignatures());
		List<XmlValidationProcessTimestamps> validationProcessTimestamps = xmlSignature.getValidationProcessTimestamps();
		if (Utils.isCollectionNotEmpty(validationProcessTimestamps)) {
			for (XmlValidationProcessTimestamps xmlValidationProcessTimestamps : validationProcessTimestamps) {
				collectInfos(infos, xmlValidationProcessTimestamps);
			}
		}
		collectInfos(infos, xmlSignature.getValidationProcessLongTermData());
		collectInfos(infos, xmlSignature.getValidationProcessArchivalData());
		return infos;
	}

	private void collectInfos(Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null) {
			if (Utils.isCollectionNotEmpty(constraintConclusion.getConstraint())) {
				for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
					collectInfos(result, getBasicBuildingBlockById(constraint.getId()));
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

	private void addCounterSignature(SignatureWrapper signature, XmlSignature xmlSignature) {
		if (signature.isCounterSignature()) {
			xmlSignature.setCounterSignature(true);
			xmlSignature.setParentId(signature.getParentId());
		}
	}

	private void addSignatureScope(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		List<eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope scopeType : signatureScopes) {
				XmlSignatureScope scope = new XmlSignatureScope();
				scope.setName(scopeType.getName());
				scope.setScope(scopeType.getScope());
				scope.setValue(scopeType.getValue());
				xmlSignature.getSignatureScope().add(scope);
			}
		}
	}

	private void addSigningTime(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		xmlSignature.setSigningTime(signature.getDateTime());
	}

	private void addSignatureFormat(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		xmlSignature.setSignatureFormat(signature.getSignatureFormat());
	}

	private String getSignedBy(final SignatureWrapper signature) {
		return getReadableCertificateName(signature.getSigningCertificateId());
	}

	private String getReadableCertificateName(String certId) {
		CertificateWrapper signingCert = diagnosticData.getUsedCertificateById(certId);
		if (signingCert != null) {
			if (Utils.isStringNotEmpty(signingCert.getCommonName())) {
				return signingCert.getCommonName();
			}
			if (Utils.isStringNotEmpty(signingCert.getGivenName())) {
				return signingCert.getGivenName();
			}
			if (Utils.isStringNotEmpty(signingCert.getSurname())) {
				return signingCert.getSurname();
			}
			if (Utils.isStringNotEmpty(signingCert.getPseudo())) {
				return signingCert.getPseudo();
			}
			if (Utils.isStringNotEmpty(signingCert.getOrganizationName())) {
				return signingCert.getOrganizationName();
			}
			if (Utils.isStringNotEmpty(signingCert.getOrganizationalUnit())) {
				return signingCert.getOrganizationalUnit();
			}
		}
		return "?";
	}

	private void addSignatureProfile(XmlValidationSignatureQualification signQualificationBlock, final XmlSignature xmlSignature) {
		if (signQualificationBlock != null) {
			SignatureQualification qualification = signQualificationBlock.getSignatureQualification();
			if (qualification != null) {
				XmlSignatureLevel sigLevel = new XmlSignatureLevel();
				sigLevel.setValue(qualification);
				sigLevel.setDescription(qualification.getLabel());
				xmlSignature.setSignatureLevel(sigLevel);
			}
		}
	}

}
