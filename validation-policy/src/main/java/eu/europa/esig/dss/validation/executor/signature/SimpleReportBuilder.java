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
package eu.europa.esig.dss.validation.executor.signature;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificate;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestampLevel;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.AbstractSimpleReportBuilder;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data and detailed validation report.
 */
public class SimpleReportBuilder extends AbstractSimpleReportBuilder {

	private int totalSignatureCount = 0;
	private int validSignatureCount = 0;

	public SimpleReportBuilder(Date currentTime, ValidationPolicy policy, DiagnosticData diagnosticData, DetailedReport detailedReport) {
		super(currentTime, policy, diagnosticData, detailedReport);
	}

	/**
	 * This method generates the validation simpleReport.
	 *
	 * @return the object representing {@code XmlSimpleReport}
	 */
	@Override
	public XmlSimpleReport build() {
		
		validSignatureCount = 0;
		totalSignatureCount = 0;

		XmlSimpleReport simpleReport = super.build();

		boolean containerInfoPresent = diagnosticData.isContainerInfoPresent();
		
		Set<String> attachedTimestampIds = new HashSet<String>();
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			attachedTimestampIds.addAll(signature.getTimestampIdsList());
			simpleReport.getSignatureOrTimestamp().add(getSignature(signature, containerInfoPresent));
		}
		
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (attachedTimestampIds.contains(timestamp.getId())) {
				continue;
			}
			simpleReport.getSignatureOrTimestamp().add(getXmlTimestamp(timestamp));
		}

		addStatistics(simpleReport);

		return simpleReport;
	}

	private void addStatistics(XmlSimpleReport simpleReport) {
		simpleReport.setValidSignaturesCount(validSignatureCount);
		simpleReport.setSignaturesCount(totalSignatureCount);
	}

	/**
	 * Builds a XmlSignature object
	 * 
	 * @param signature
	 *                  the signature wrapper
	 * @param container
	 *                  true if the current file is a container
	 */
	private XmlSignature getSignature(SignatureWrapper signature, boolean container) {

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

		xmlSignature.setCertificateChain(getCertChain(signatureId));
		return xmlSignature;
	}

	public XmlCertificateChain getCertChain(String tokenId) {
		List<String> certIds = detailedReport.getBasicBuildingBlocksCertChain(tokenId);
		XmlCertificateChain xmlCertificateChain = new XmlCertificateChain();
		if (Utils.isCollectionNotEmpty(certIds)) {
			for (String certid : certIds) {
				XmlCertificate certificate = new XmlCertificate();
				certificate.setId(certid);
				certificate.setQualifiedName(getReadableCertificateName(certid));
				xmlCertificateChain.getCertificate().add(certificate);
			}
		}
		return xmlCertificateChain;
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

	private XmlTimestamp getXmlTimestamp(TimestampWrapper timestampWrapper) {
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setId(timestampWrapper.getId());
		xmlTimestamp.setProductionTime(timestampWrapper.getProductionTime());
		xmlTimestamp.setProducedBy(getProducedByName(timestampWrapper));
		xmlTimestamp.setCertificateChain(getCertChain(timestampWrapper.getId()));
		xmlTimestamp.setFilename(timestampWrapper.getFilename());

		XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampWrapper.getId());
		xmlTimestamp.setIndication(timestampBBB.getConclusion().getIndication());
		xmlTimestamp.setSubIndication(timestampBBB.getConclusion().getSubIndication());
		xmlTimestamp.getErrors().addAll(toStrings(timestampBBB.getConclusion().getErrors()));
		xmlTimestamp.getWarnings().addAll(toStrings(timestampBBB.getConclusion().getWarnings()));
		xmlTimestamp.getInfos().addAll(toStrings(timestampBBB.getConclusion().getInfos()));

		TimestampQualification timestampQualification = detailedReport.getTimestampQualification(timestampWrapper.getId());
		if (timestampQualification != null) {
			XmlTimestampLevel xmlTimestampLevel = new XmlTimestampLevel();
			xmlTimestampLevel.setValue(timestampQualification);
			xmlTimestampLevel.setDescription(timestampQualification.getLabel());
			xmlTimestamp.setTimestampLevel(xmlTimestampLevel);
		}

		return xmlTimestamp;
	}

	private String getProducedByName(TimestampWrapper timestampWrapper) {
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getReadableCertificateName();
		}
		return Utils.EMPTY_STRING;
	}

	private List<String> toStrings(List<XmlName> xmlNames) {
		List<String> strings = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(xmlNames)) {
			for (XmlName name : xmlNames) {
				strings.add(name.getValue());
			}
		}
		return strings;
	}

}
