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
package eu.europa.esig.dss.asic.signature.asics;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.junit.Before;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.signature.AbstractTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class ASiCSCAdESLevelBWithMimeTypeTest extends AbstractTestDocumentSignatureService<ASiCWithCAdESSignatureParameters> {

	private static final String APPLICATION_VND_OASIS_OPENDOCUMENT_TEXT = "application/vnd.oasis.opendocument.text";
	private DocumentSignatureService<ASiCWithCAdESSignatureParameters> service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
		signatureParameters.aSiC().setMimeType(APPLICATION_VND_OASIS_OPENDOCUMENT_TEXT);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new ASiCWithCAdESService(certificateVerifier);
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		InMemoryDocument doc = new InMemoryDocument(byteArray);

		AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(doc);
		ASiCExtractResult extract = extractor.extract();
		DSSDocument mimeTypeDocument = extract.getMimeTypeDocument();
		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		try {
			assertEquals(APPLICATION_VND_OASIS_OPENDOCUMENT_TEXT, new String(mimeTypeContent, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail(e.getMessage());
		}
	}

	@Override
	protected DocumentSignatureService<ASiCWithCAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.ASICS;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}

}
