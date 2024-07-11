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
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author axel.abinet
 *
 */
class CAdESDoubleSignatureTest extends AbstractCAdESTestSignature {

	private static DSSDocument originalDocument;
	private static Date date;
	
	private static String firstSignatureId;
	private static String secondSignatureId;
	
	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeAll
	static void initBeforeAll() {
		originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
		date = new Date();
	}

	@BeforeEach
	void init() throws Exception {
		documentToSign = originalDocument;

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(date);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();
		documentToSign = signedDocument;
		DSSDocument doubleSignedDocument = super.sign();
		documentToSign = originalDocument;
		return doubleSignedDocument;
	}

	@RepeatedTest(10)
	@Override
	public void signAndVerify() {
		super.signAndVerify();
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(2, diagnosticData.getSignatures().size());
	}

	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		assertEquals(4, diagnosticData.getTimestampList().size());
	}

	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		super.checkSignatureIdentifier(diagnosticData);

		SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
		SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
		assertNotEquals(signatureOne.getId(), signatureTwo.getId());
		if (firstSignatureId == null) {
			firstSignatureId = signatureOne.getId();
			secondSignatureId = signatureTwo.getId();
		}
		assertEquals(firstSignatureId, signatureOne.getId());
		assertEquals(secondSignatureId, signatureTwo.getId());
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		boolean textMimeTypeFound = false;
		boolean binaryMimeTypeFound = false;
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getMimeType());

			MimeType mimeType = MimeType.fromMimeTypeString(signatureWrapper.getMimeType());
			assertNotNull(mimeType);

			if (MimeTypeEnum.TEXT.equals(mimeType)) {
				textMimeTypeFound = true;
			} else if (MimeTypeEnum.BINARY.equals(mimeType)) {
				binaryMimeTypeFound = true;
			}
		}
		assertTrue(textMimeTypeFound);
		assertTrue(binaryMimeTypeFound);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
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
