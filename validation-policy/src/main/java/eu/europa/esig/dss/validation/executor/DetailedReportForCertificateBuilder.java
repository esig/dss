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

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertificateQualificationBlock;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DetailedReportForCertificateBuilder extends AbstractDetailedReportBuilder {

	private final String certificateId;

	public DetailedReportForCertificateBuilder(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime, String certificateId) {
		super(diagnosticData, policy, currentTime);
		this.certificateId = certificateId;
	}

	DetailedReport build() {

		DetailedReport detailedReport = init();

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();

		Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<String, XmlBasicBuildingBlocks>();
		process(Collections.singleton(certificate), Context.CERTIFICATE, bbbs);
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		XmlBasicBuildingBlocks basicBuildingBlocks = bbbs.get(certificate.getId());

		CertificateQualificationBlock cqb = new CertificateQualificationBlock(basicBuildingBlocks.getConclusion(), currentTime, certificate, usedCertificates,
				detailedReport.getTLAnalysis(), diagnosticData.getLOTLCountryCode());
		detailedReport.setCertificate(cqb.execute());

		return detailedReport;
	}

}
