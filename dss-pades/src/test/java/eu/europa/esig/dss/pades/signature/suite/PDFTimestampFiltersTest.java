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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PDFTimestampFiltersTest extends AbstractPAdESTestSignature {

	private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	@BeforeEach
	void init() throws Exception {
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
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertTrue(Utils.isCollectionNotEmpty(timestampList));
		assertEquals(2, timestampList.size());
		
		boolean signatureTimestampFound = false;
		boolean docTimestampFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP == timestampWrapper.getType()) {
				assertNull(timestampWrapper.getPDFRevision()); // signature timestamp is added to CAdES CMS
				signatureTimestampFound = true;
				
			} else if (TimestampType.DOCUMENT_TIMESTAMP == timestampWrapper.getType()) {
				PDFRevisionWrapper pdfRevision = timestampWrapper.getPDFRevision();
				assertNotNull(pdfRevision);
				
				assertEquals("Adobe.PPKLite", pdfRevision.getFilter());
				assertEquals("ETSI.RFC3161", pdfRevision.getSubFilter());

				docTimestampFound = true;
				
			}
		}
		
		assertTrue(signatureTimestampFound);
		assertTrue(docTimestampFound);
	}


	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

}
