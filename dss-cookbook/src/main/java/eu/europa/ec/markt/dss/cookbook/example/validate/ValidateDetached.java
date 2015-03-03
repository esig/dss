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
package eu.europa.ec.markt.dss.cookbook.example.validate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.cookbook.mock.MockServiceInfo;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonTrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * How to validate a PADES-BASELINE-B DETACHED signature.
 */
public class ValidateDetached extends Cookbook {

	public static void main(String[] args) throws IOException {

		preparePKCS12TokenAndKey();

		final CertificateToken[] certificateChain = privateKey.getCertificateChain();
		final CertificateToken trustedCertificate = certificateChain[0];

		// Already signed document
		DSSDocument document = new FileDocument("target/signedPdfPadesBDetached.pdf");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();

		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		ServiceInfo mockServiceInfo = new MockServiceInfo();
		commonTrustedCertificateSource.addCertificate(trustedCertificate, mockServiceInfo);
		verifier.setTrustedCertSource(commonTrustedCertificateSource);

		validator.setCertificateVerifier(verifier);

		//DOCUMENT TO SIGN
		List<DSSDocument> detachedContentsList = new ArrayList<DSSDocument>();
		String detachedFilePath = getPathFromResource("/hello-world.pdf");
		DSSDocument detachedContents = new FileDocument(detachedFilePath);
		detachedContentsList.add(detachedContents);
		validator.setDetachedContents(detachedContentsList);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SimpleReport simpleReport = reports.getSimpleReport();

		InputStream is = new ByteArrayInputStream(simpleReport.toByteArray());
		DSSUtils.saveToFile(is, "target/validationDetached_simpleReport.xml");
		is = new ByteArrayInputStream(diagnosticData.toByteArray());
		DSSUtils.saveToFile(is, "target/validationDetached_diagnosticReport.xml");

		//System.out.println(diagnosticData);
	}
}
