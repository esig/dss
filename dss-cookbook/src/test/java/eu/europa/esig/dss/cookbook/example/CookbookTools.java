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
package eu.europa.esig.dss.cookbook.example;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CookbookTools extends PKIFactoryAccess {

	/**
	 * The document to sign
	 */
	static protected DSSDocument toSignDocument;

	/**
	 * This method sets the common parameters.
	 */
	protected static void prepareXmlDoc() {
		toSignDocument = new FileDocument(new File("src/main/resources/xml_example.xml"));
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void preparePdfDoc() {
		toSignDocument = new FileDocument(new File("src/main/resources/hello-world.pdf"));
	}

	protected DiagnosticData testFinalDocument(DSSDocument signedDocument) {
		return testFinalDocument(signedDocument, null);
	}

	protected DiagnosticData testFinalDocument(DSSDocument signedDocument, List<DSSDocument> detachedContents) {
		assertNotNull(signedDocument);
		assertNotNull(DSSUtils.toByteArray(signedDocument));

		SignedDocumentValidator validator = getValidator(signedDocument);
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			validator.setDetachedContents(detachedContents);
		}
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper signatureWrapper : signatures) {
			assertTrue(signatureWrapper.isBLevelTechnicallyValid());

			List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
			for (TimestampWrapper timestampWrapper : timestampList) {
				assertTrue(timestampWrapper.isMessageImprintDataFound());
				assertTrue(timestampWrapper.isMessageImprintDataIntact());
				assertTrue(timestampWrapper.isSignatureValid());
			}
		}

		return diagnosticData;
	}

	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		return validator;
	}

	/**
	 * This method retrieves an instance of online PKCS12 keystore
	 *
	 */
	protected SignatureTokenConnection getUserPkcs12Token() throws IOException {
		return getOnlinePKCS12Token();
	}

	/**
	 * This method retrieves an instance of PKCS12 keystore
	 * 
	 */
	protected SignatureTokenConnection getPkcs12Token() throws IOException {
		return getToken();
	}

	protected TSPSource getOnlineTSPSource() {
		return getOnlineTSPSourceByName(GOOD_TSA);
	}

	@Override
	protected CertificateSource getTrustedCertificateSource() {
		CertificateSource trustedCertificateSource = super.getTrustedCertificateSource();
		getOnlineTrustedCertificateSource().getCertificates().forEach(trustedCertificateSource::addCertificate);
		return trustedCertificateSource;
	}

	protected TSPSource getTSPSource() {
		return getPKITSPSourceByName(GOOD_TSA);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
