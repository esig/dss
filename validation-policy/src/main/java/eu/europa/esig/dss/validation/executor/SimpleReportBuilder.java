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
import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder {

	private final Date currentTime;
	private final ValidationPolicy policy;
	private final DiagnosticData diagnosticData;
	private final DetailedReport detailedReport;

	private int totalSignatureCount = 0;
	private int validSignatureCount = 0;

	public SimpleReportBuilder(Date currentTime, ValidationPolicy policy, DiagnosticData diagnosticData, DetailedReport detailedReport) {
		this.currentTime = currentTime;
		this.policy = policy;
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @return the object representing {@code XmlSimpleReport}
	 */
	public XmlSimpleReport build() {

		XmlSimpleReport simpleReport = new XmlSimpleReport();

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

	private void addPolicyNode(XmlSimpleReport report) {
		XmlPolicy xmlpolicy = new XmlPolicy();
		xmlpolicy.setPolicyName(policy.getPolicyName());
		xmlpolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setPolicy(xmlpolicy);
	}

	private void addValidationTime(XmlSimpleReport report) {
		report.setValidationTime(currentTime);
	}

	private void addDocumentName(XmlSimpleReport report) {
		report.setDocumentName(diagnosticData.getDocumentName());
	}

	private void addContainerType(XmlSimpleReport simpleReport) {
		simpleReport.setContainerType(diagnosticData.getContainerType());
	}

	private void addSignatures(XmlSimpleReport simpleReport, boolean container) {
		validSignatureCount = 0;
		totalSignatureCount = 0;
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper signature : signatures) {
			addSignature(simpleReport, signature, container);
		}
	}

	private void addStatistics(XmlSimpleReport simpleReport) {
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
	private void addSignature(XmlSimpleReport simpleReport, SignatureWrapper signature, boolean container) {

		totalSignatureCount++;

		String signatureId = signature.getId();
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setId(signatureId);

		addCounterSignature(signature, xmlSignature);
		addSignatureScope(signature, xmlSignature);
		addSigningTime(signature, xmlSignature);
		addBestSignatureTime(signature, xmlSignature);
		addSignatureFormat(signature, xmlSignature);

		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		if (signingCertificate != null) {
			xmlSignature.setSignedBy(getReadableCertificateName(signingCertificate.getId()));
		}

		xmlSignature.getErrors().addAll(detailedReport.getErrors(signatureId));
		xmlSignature.getWarnings().addAll(detailedReport.getWarnings(signatureId));
		xmlSignature.getInfos().addAll(detailedReport.getInfos(signatureId));

		if (container) {
			xmlSignature.setFilename(signature.getSignatureFilename());
		}

		Indication indication = detailedReport.getHighestIndication(signatureId);
		if (Indication.PASSED.equals(indication)) {
			validSignatureCount++;
			xmlSignature.setIndication(Indication.TOTAL_PASSED);
		} else if (Indication.FAILED.equals(indication)) {
			xmlSignature.setIndication(Indication.TOTAL_FAILED);
		} else {
			xmlSignature.setIndication(indication); // INDERTERMINATE
		}
		xmlSignature.setSubIndication(detailedReport.getHighestSubIndication(signatureId));

		addSignatureProfile(xmlSignature);

		List<String> certIds = detailedReport.getBasicBuildingBlocksCertChain(signatureId);
		XmlCertificateChain xmlCertificateChain = new XmlCertificateChain();
		if (Utils.isCollectionNotEmpty(certIds)) {
			for (String certid : certIds) {
				XmlCertificate certificate = new XmlCertificate();
				certificate.setId(certid);
				certificate.setQualifiedName(getReadableCertificateName(certid));
				xmlCertificateChain.getCertificate().add(certificate);
			}
		}
		xmlSignature.setCertificateChain(xmlCertificateChain);

		simpleReport.getSignature().add(xmlSignature);
	}

	private void addBestSignatureTime(SignatureWrapper signature, XmlSignature xmlSignature) {
		xmlSignature.setBestSignatureTime(detailedReport.getBestSignatureTime(signature.getId()));
	}

	private void addCounterSignature(SignatureWrapper signature, XmlSignature xmlSignature) {
		if (signature.isCounterSignature()) {
			xmlSignature.setCounterSignature(true);
			xmlSignature.setParentId(signature.getParent().getId());
		}
	}

	private void addSignatureScope(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope scopeType : signatureScopes) {
				XmlSignatureScope scope = new XmlSignatureScope();
				scope.setName(scopeType.getName());
				scope.setScope(scopeType.getScope().name());
				scope.setValue(scopeType.getDescription());
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

	private String getReadableCertificateName(final String certId) {
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateByIdNullSafe(certId);
		return certificateWrapper.getReadableCertificateName();
	}

	private void addSignatureProfile(final XmlSignature xmlSignature) {
		SignatureQualification qualification = detailedReport.getSignatureQualification(xmlSignature.getId());
		if (qualification != null) {
			XmlSignatureLevel sigLevel = new XmlSignatureLevel();
			sigLevel.setValue(qualification);
			sigLevel.setDescription(qualification.getLabel());
			xmlSignature.setSignatureLevel(sigLevel);
		}
	}

}
