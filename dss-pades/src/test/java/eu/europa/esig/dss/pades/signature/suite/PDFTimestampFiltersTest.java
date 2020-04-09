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
package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PDFTimestampFiltersTest extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@Test
	public void test() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		
		PAdESTimestampParameters signatureTimestampParameters = new PAdESTimestampParameters();
		signatureTimestampParameters.setFilter("signatureTspFilter");
		signatureTimestampParameters.setSubFilter("signatureTspSubFilter");
		signatureParameters.setSignatureTimestampParameters(signatureTimestampParameters);
		
		PAdESTimestampParameters archivalTimestampParameters = new PAdESTimestampParameters();
		archivalTimestampParameters.setFilter("Adobe.PPKLite");
		archivalTimestampParameters.setSubFilter("ETSI.RFC3161");
		signatureParameters.setArchiveTimestampParameters(archivalTimestampParameters);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(timestampList));
		assertEquals(2, timestampList.size());
		
		boolean signatureTimestampFound = false;
		boolean archivalTimestampFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
				assertNull(timestampWrapper.getPDFRevision()); // signature timestamp is added to CAdES CMS
				signatureTimestampFound = true;
				
			} else if (TimestampType.ARCHIVE_TIMESTAMP == timestampWrapper.getType()) {
				XmlPDFRevision pdfRevision = timestampWrapper.getPDFRevision();
				assertNotNull(pdfRevision);
				
				XmlPDFSignatureDictionary pdfSignatureDictionary = pdfRevision.getPDFSignatureDictionary();
				assertNotNull(pdfSignatureDictionary);
				
				assertEquals("Adobe.PPKLite", pdfSignatureDictionary.getFilter());
				assertEquals("ETSI.RFC3161", pdfSignatureDictionary.getSubFilter());
				
				archivalTimestampFound = true;
				
			}
		}
		
		assertTrue(signatureTimestampFound);
		assertTrue(archivalTimestampFound);
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
