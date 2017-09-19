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
package eu.europa.esig.dss.cookbook.example.validate;

import java.io.IOException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.cookbook.example.Cookbook;
import eu.europa.esig.dss.cookbook.mock.MockServiceInfo;
import eu.europa.esig.dss.cookbook.mock.MockTSLCertificateSource;
import eu.europa.esig.dss.cookbook.sources.AlwaysValidOCSPSource;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * How to validate a signature with a custom validation policy.
 */
public class ValidateSignedXmlXadesBWithCustomPolicy extends Cookbook {

	@SuppressWarnings("unused")
	public static void main(String[] args) throws IOException {

		// To be able to validate our fake signature, we must define one of the certificates in the chain as trusted
		// anchor.
		// If you have a real signature for which it is possible to build the chain till the TSL then just skip this
		// point.
		preparePKCS12TokenAndKey();
		final CertificateToken[] certificateChain = privateKey.getCertificateChain();
		final CertificateToken trustedCertificate = certificateChain[0];

		DSSDocument document = new FileDocument("target/signedXmlXadesB.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();

		AlwaysValidOCSPSource ocspSource = new AlwaysValidOCSPSource();
		verifier.setOcspSource(ocspSource);

		MockTSLCertificateSource trustedCertSource = new MockTSLCertificateSource();
		ServiceInfo mockServiceInfo = new MockServiceInfo();
		trustedCertSource.addCertificate(trustedCertificate, mockServiceInfo);

		verifier.setTrustedCertSource(trustedCertSource);
		validator.setCertificateVerifier(verifier);

		Reports reports = validator.validateDocument(getPathFromResource("/constraint.xml"));
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		DetailedReport detailedReport = reports.getDetailedReport();
		SimpleReport simpleReport = reports.getSimpleReport();
	}
}
