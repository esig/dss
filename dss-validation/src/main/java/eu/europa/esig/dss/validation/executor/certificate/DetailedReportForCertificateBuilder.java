/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor.certificate;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateQualificationProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificateApprovalStatusProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.AbstractDetailedReportBuilder;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertificateQualificationBlock;
import eu.europa.esig.dss.validation.process.qualification.certificate.usage.CertificateApprovalStatusBlock;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Builds a DetailedReport for a certificate validation
 */
public class DetailedReportForCertificateBuilder extends AbstractDetailedReportBuilder {

	/** Id of a certificate to validate */
	private final String certificateId;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param diagnosticData {@link DiagnosticData}
	 * @param policy {@link ValidationPolicy}
	 * @param currentTime {@link Date} validation time
	 * @param certificateId {@link String} id of a certificate to be validated
	 */
	public DetailedReportForCertificateBuilder(I18nProvider i18nProvider, DiagnosticData diagnosticData, 
			ValidationPolicy policy, Date currentTime, String certificateId) {
		super(i18nProvider, currentTime, policy, diagnosticData);
		this.certificateId = certificateId;
	}

	/**
	 * Builds the detailed report for the certificate validation
	 *
	 * @return {@link XmlDetailedReport}
	 */
	public XmlDetailedReport build() {
		XmlDetailedReport detailedReport = init();

		Map<String, XmlBasicBuildingBlocks> bbbs = executeAllBasicBuildingBlocks();
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		executeValidation(detailedReport, bbbs);
		return detailedReport;
	}

	/**
	 * Gets the certificate to be validated
	 *
	 * @return {@link CertificateWrapper}
	 */
	protected CertificateWrapper getCertificate() {
		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		if (certificate == null) {
			throw new IllegalArgumentException(String.format(
					"The certificate with the given Id '%s' has not been found in DiagnosticData", certificateId));
		}
		return certificate;
	}

	/**
	 * This method executes all basic building blocks required on validation
	 *
	 * @return a map of {@link XmlBasicBuildingBlocks} and corresponding token identifiers
	 */
	protected Map<String, XmlBasicBuildingBlocks> executeAllBasicBuildingBlocks() {
		final Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();
		process(Collections.singleton(getCertificate()), Context.CERTIFICATE, bbbs);
		return bbbs;
	}

	/**
	 * Performs validation for the given tokens
	 *
	 * @param detailedReport {@link XmlDetailedReport}
	 * @param bbbs map of {@link XmlBasicBuildingBlocks}
	 */
	protected void executeValidation(XmlDetailedReport detailedReport, Map<String, XmlBasicBuildingBlocks> bbbs) {
		buildXmlCertificate(detailedReport, bbbs);
	}

	/**
	 * Executes certificate validation and builds a {@code XmlCertificate} object
	 *
	 * @param detailedReport {@link XmlDetailedReport}
	 * @param bbbs map of {@link XmlBasicBuildingBlocks}
	 * @return {@link XmlCertificate}
	 */
	protected XmlCertificate buildXmlCertificate(XmlDetailedReport detailedReport, Map<String, XmlBasicBuildingBlocks> bbbs) {
		XmlBasicBuildingBlocks basicBuildingBlocks = bbbs.get(certificateId);

		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId(certificateId);

		CertificateQualificationBlock cqb = getCertificateQualificationBlock(detailedReport, basicBuildingBlocks);
		XmlCertificateQualificationProcess xmlCertificateQualificationProcess = cqb.execute();
		xmlCertificate.setCertificateQualificationProcess(xmlCertificateQualificationProcess);

		if (validateCertificateApprovalStatus()) {
			CertificateApprovalStatusBlock cub = getCertificateApprovalStatusBlock(detailedReport, basicBuildingBlocks);
			XmlCertificateApprovalStatusProcess xmlCertificateApprovalStatusProcess = cub.execute();
			xmlCertificate.setCertificateApprovalStatusProcess(xmlCertificateApprovalStatusProcess);
		}

		detailedReport.getSignatureOrTimestampOrEvidenceRecord().add(xmlCertificate);

		return xmlCertificate;
	}

	/**
	 * Gets the certificate qualification block
	 *
	 * @param detailedReport {@link XmlDetailedReport}
	 * @param basicBuildingBlocks {@link XmlBasicBuildingBlocks}
	 * @return {@link CertificateQualificationBlock}
	 */
	protected CertificateQualificationBlock getCertificateQualificationBlock(XmlDetailedReport detailedReport, XmlBasicBuildingBlocks basicBuildingBlocks) {
		return new CertificateQualificationBlock(i18nProvider, basicBuildingBlocks.getConclusion(), currentTime,
				getCertificate(), detailedReport.getTLAnalysis());
	}

	/**
	 * Gets the certificate approval revocation block
	 *
	 * @param detailedReport {@link XmlDetailedReport}
	 * @param basicBuildingBlocks {@link XmlBasicBuildingBlocks}
	 * @return {@link CertificateApprovalStatusBlock}
	 */
	protected CertificateApprovalStatusBlock getCertificateApprovalStatusBlock(XmlDetailedReport detailedReport, XmlBasicBuildingBlocks basicBuildingBlocks) {
		return new CertificateApprovalStatusBlock(i18nProvider, basicBuildingBlocks.getConclusion(), currentTime,
				getCertificate(), detailedReport.getLoTEAnalysis());
	}

	/**
	 * Checks if the certificate approval revocation is to be validated
	 *
	 * @return TRUE if to validate the certificate approval revocation, FALSE otherwise
	 */
	protected boolean validateCertificateApprovalStatus() {
		return Utils.isCollectionNotEmpty(diagnosticData.getListsOfTrustedEntities());
	}

}
