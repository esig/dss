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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCECAdESLevelLTATest extends AbstractASiCECAdESTestSignature {

	private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		ASiCWithCAdESContainerExtractor containerExtractor = new ASiCWithCAdESContainerExtractor(new InMemoryDocument(byteArray));
		ASiCContent result = containerExtractor.extract();

		List<DSSDocument> signatureDocuments = result.getSignatureDocuments();
		assertTrue(Utils.isCollectionNotEmpty(signatureDocuments));
		for (DSSDocument signatureDocument : signatureDocuments) {
			// validate with no detached content
			DiagnosticData diagnosticData = validateDocument(signatureDocument);
			SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
			assertEquals(1, digestMatchers.size());
			assertFalse(digestMatchers.get(0).isDataFound());
			assertFalse(digestMatchers.get(0).isDataIntact());

			// with detached content
			diagnosticData = validateDocument(signatureDocument, Arrays.asList(getSignedData(result)));
			signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			digestMatchers = signature.getDigestMatchers();
			assertEquals(1, digestMatchers.size());
			assertTrue(digestMatchers.get(0).isDataFound());
			assertTrue(digestMatchers.get(0).isDataIntact());
		}
	}

	private DiagnosticData validateDocument(DSSDocument signatureDocument) {
		return validateDocument(signatureDocument, null);
	}

	private DiagnosticData validateDocument(DSSDocument signatureDocument, List<DSSDocument> detachedContents) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			validator.setDetachedContents(detachedContents);
		}
		Reports reports = validator.validateDocument();
		return reports.getDiagnosticData();
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		String signatureId = diagnosticData.getFirstSignatureId();
		for (TimestampWrapper wrapper : diagnosticData.getTimestampList(signatureId)) {
			boolean found = false;
			for (SignatureWrapper signatureWrapper : wrapper.getTimestampedSignatures()) {
				if (signatureId.equals(signatureWrapper.getId())) {
					found = true;
				}
			}
			assertTrue(found);
		}
	}

	@Override
	protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
