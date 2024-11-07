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
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.AbstractDetailedReportBuilder;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertificateQualificationBlock;

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
	XmlDetailedReport build() {

		XmlDetailedReport detailedReport = init();

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		if (certificate == null) {
			throw new IllegalArgumentException(String.format("The certificate with the given Id '%s' has not been found in DiagnosticData", certificateId));
		}

		Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<>();
		process(Collections.singleton(certificate), Context.CERTIFICATE, bbbs);
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		XmlBasicBuildingBlocks basicBuildingBlocks = bbbs.get(certificate.getId());

		CertificateQualificationBlock cqb = new CertificateQualificationBlock(i18nProvider, basicBuildingBlocks.getConclusion(), currentTime, certificate,
				detailedReport.getTLAnalysis());
		detailedReport.getSignatureOrTimestampOrEvidenceRecord().add(cqb.execute());

		return detailedReport;
	}

}
