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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.io.UnsupportedEncodingException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCSCAdESLevelBWithODTFileTest extends AbstractASiCSCAdESTestSignature {

	private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument("src/test/resources/signable/document.odt");

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		InMemoryDocument doc = new InMemoryDocument(byteArray);

		AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(doc);
		ASiCContent extract = extractor.extract();

		assertEquals(0, extract.getUnsupportedDocuments().size());

		List<DSSDocument> signatureDocuments = extract.getSignatureDocuments();
		assertEquals(1, signatureDocuments.size());
		String signatureFilename = signatureDocuments.get(0).getName();
		assertTrue(signatureFilename.startsWith("META-INF/signature"));
		assertTrue(signatureFilename.endsWith(".p7s"));

		List<DSSDocument> manifestDocuments = extract.getManifestDocuments();
		assertEquals(0, manifestDocuments.size());

		List<DSSDocument> signedDocuments = extract.getSignedDocuments();
		assertEquals(1, signedDocuments.size());
		assertEquals("document.odt", signedDocuments.get(0).getName());

		DSSDocument mimeTypeDocument = extract.getMimeTypeDocument();

		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		try {
			assertEquals(MimeType.ASICS.getMimeTypeString(), new String(mimeTypeContent, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail(e.getMessage());
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
