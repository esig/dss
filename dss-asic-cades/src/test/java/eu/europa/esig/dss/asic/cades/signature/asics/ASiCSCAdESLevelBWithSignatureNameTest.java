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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSCAdESLevelBWithSignatureNameTest extends AbstractASiCSCAdESTestSignature {

	private static final String SIGNATURE_FILENAME = "signature-toto.p7s";
	private ASiCWithCAdESService service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		SimpleASiCWithCAdESFilenameFactory asicFilenameFactory = new SimpleASiCWithCAdESFilenameFactory();
		asicFilenameFactory.setSignatureFilename(SIGNATURE_FILENAME);
		getService().setAsicFilenameFactory(asicFilenameFactory);

		Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
		assertEquals("A signature file within ASiC-S with CAdES container shall have name " +
				"'META-INF/signature.p7s'!", exception.getMessage());

		asicFilenameFactory.setSignatureFilename("META-INF/signature.p7s");
		return super.sign();
	}

	@Override
	protected void checkExtractedContent(ASiCContent asicContent) {
		assertEquals(0, asicContent.getUnsupportedDocuments().size());

		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		assertEquals(1, signatureDocuments.size());
		assertEquals("META-INF/signature.p7s", signatureDocuments.get(0).getName());

		List<DSSDocument> manifestDocuments = asicContent.getManifestDocuments();
		assertEquals(0, manifestDocuments.size());

		List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
		assertEquals(1, signedDocuments.size());
		assertEquals("test.text", signedDocuments.get(0).getName());

		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();

		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		assertEquals(MimeTypeEnum.ASICS.getMimeTypeString(), new String(mimeTypeContent, StandardCharsets.UTF_8));

		assertTrue(Utils.isStringEmpty(asicContent.getZipComment()));

	}

	@Override
	protected ASiCWithCAdESService getService() {
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
