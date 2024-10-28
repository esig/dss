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
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.io.IOException;
import java.util.Date;

@Tag("slow")
class PAdESVisibleDocRotationTest extends AbstractTestVisualComparator {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private String testName;

	@BeforeEach
	void init(TestInfo testInfo) {
		testName = testInfo.getTestMethod().get().getName();
		
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/rotate90-rotated.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());
	}
	
	@Test
	void test() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setZoom(50);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	void testHorizontalAlignment() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setZoom(50);
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.CENTER);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	void testVerticalAlignment() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(getPngPicture());
		imageParameters.setZoom(50);
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	private DSSDocument getPngPicture() {
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG);
	}

	@Override
	protected String getTestName() {
		return testName;
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

}
