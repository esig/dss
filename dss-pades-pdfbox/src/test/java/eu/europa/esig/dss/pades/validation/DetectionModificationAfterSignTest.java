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
package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.imageio.ImageIO;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.pades.PdfScreenshotUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class DetectionModificationAfterSignTest {

	@Test
	public void testWithModification() throws IOException {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/modified_after_signature.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		AdvancedSignature advancedSignature = signatures.get(0);

		List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(advancedSignature.getId());
		assertEquals(1, retrievedDocuments.size());
		DSSDocument retrievedDocument = retrievedDocuments.get(0);

		DSSDocument expected = new InMemoryDocument(getClass().getResourceAsStream("/validation/retrieved-modified_after_signature.pdf"));
		assertEquals(expected.getDigest64Base(DigestAlgorithm.SHA256), retrievedDocument.getDigest64Base(DigestAlgorithm.SHA256));

		// Additional code to detect visual difference
		BufferedImage differenceImage = PdfScreenshotUtils.getDifferenceImage(dssDocument, expected);
		ImageIO.write(differenceImage, "PNG", new File("target/diff.png"));
	}

}
