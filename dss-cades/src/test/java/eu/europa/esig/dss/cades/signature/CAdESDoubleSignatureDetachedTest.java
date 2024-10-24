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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CAdESDoubleSignatureDetachedTest extends AbstractCAdESTestSignature {
	
	private DSSDocument documentToSign;
	private CAdESSignatureParameters parameters;
	private CAdESService service;

	private String user;
	
	private static DSSDocument original = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
	
	@BeforeEach
	void init() {
		documentToSign = original;
		
        user = GOOD_USER;
		
		parameters = new CAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        service = new CAdESService(getOfflineCertificateVerifier());
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(original);
	}

	@Test
	void test() throws Exception {
		DSSDocument signedDocument = sign();
		Reports reports = verify(signedDocument);
		
        byte[] expectedDigest = documentToSign.getDigestValue(DigestAlgorithm.SHA512);
		
		documentToSign = signedDocument;
		user = EE_GOOD_USER;
		
		parameters = new CAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		parameters.setDetachedContents(Collections.singletonList(original));
		
		DSSDocument resignedDocument = sign();
		
		reports = verify(resignedDocument);

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		assertEquals(2, diagnosticData.getSignatureIdList().size());

		for (String id : diagnosticData.getSignatureIdList()) {
			SignatureWrapper signatureById = diagnosticData.getSignatureById(id);
			List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
			assertEquals(1, digestMatchers.size());

			XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
			assertEquals(DigestMatcherType.MESSAGE_DIGEST, xmlDigestMatcher.getType());
			assertEquals(DigestAlgorithm.SHA512, xmlDigestMatcher.getDigestMethod());
			assertArrayEquals(expectedDigest, xmlDigestMatcher.getDigestValue());
		}

		user = EE_GOOD_USER;
		parameters = new CAdESSignatureParameters();
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		// explicit missing file
		// signatureParameters.setDetachedContents(Arrays.asList(documentToSign));

		Exception e = assertThrows(IllegalArgumentException.class, this::sign);
		assertEquals("Detached content shall be provided on parallel signing of a detached signature! " +
				"Please use cadesSignatureParameters#setDetachedContents method to provide original files.", e.getMessage());
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getMimeType());

			MimeType mimeType = MimeType.fromMimeTypeString(signatureWrapper.getMimeType());
			assertEquals(MimeTypeEnum.TEXT, mimeType);
		}
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void checkSignatureInformationStore(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		// do nothing
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	public void signAndVerify() {
		// do nothing
	}

	@Override
	protected String getSigningAlias() {
		return user;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return parameters;
	}
	
}
