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
package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZipExtractorTest extends PKIFactoryAccess {
	
	private DSSDocument openDocument;
	private DSSDocument zipArchive;
	
	
	@BeforeEach
	void init() throws Exception {
		openDocument = new FileDocument(new File("src/test/resources/signable/open-document.odt"));
		zipArchive = new FileDocument(new File("src/test/resources/signable/test.zip"));
	}
	
	@Test
	void extractUnsignedOpenDocument() {
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(openDocument);
		ASiCContent extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertTrue(Utils.isCollectionNotEmpty(extract.getManifestDocuments()));
		assertEquals(1, extract.getManifestDocuments().size());

		assertFalse(Utils.isCollectionNotEmpty(extract.getContainerDocuments()));
		assertNotNull(extract.getMimeTypeDocument());
		assertNotNull(extract.getAsicContainer());

		assertFalse(Utils.isCollectionNotEmpty(extract.getSignatureDocuments()));
		assertTrue(Utils.isCollectionNotEmpty(extract.getSignedDocuments()));
		assertEquals(12, extract.getSignedDocuments().size());
	}
	
	@Test
	void extractUnsignedZip() {
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(zipArchive);
		ASiCContent extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertFalse(Utils.isCollectionNotEmpty(extract.getManifestDocuments()));
		assertEquals(0, extract.getManifestDocuments().size());

		assertFalse(Utils.isCollectionNotEmpty(extract.getContainerDocuments()));
		assertNull(extract.getMimeTypeDocument());
		assertNotNull(extract.getAsicContainer());

		assertFalse(Utils.isCollectionNotEmpty(extract.getSignatureDocuments()));
		assertEquals(0, extract.getSignatureDocuments().size());
		assertTrue(Utils.isCollectionNotEmpty(extract.getSignedDocuments()));
		assertEquals(1, extract.getSignedDocuments().size());
	}
	
	@Test
	void extractSignedZip() {
		DSSDocument document = signDocument(zipArchive);
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
		ASiCContent extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertTrue(Utils.isCollectionNotEmpty(extract.getManifestDocuments()));
		assertEquals(1, extract.getManifestDocuments().size());

		assertFalse(Utils.isCollectionNotEmpty(extract.getContainerDocuments()));
	
		assertNotNull(extract.getMimeTypeDocument());
		MimeType mimeType = ASiCUtils.getMimeType(extract.getMimeTypeDocument());
		assertEquals("application/vnd.etsi.asic-e+zip",  mimeType.getMimeTypeString());

		assertNotNull(extract.getAsicContainer());
		
		assertTrue(Utils.isCollectionNotEmpty(extract.getSignatureDocuments()));
		assertEquals(1, extract.getSignatureDocuments().size());
		assertTrue(Utils.isCollectionNotEmpty(extract.getSignedDocuments()));
		assertEquals(1, extract.getSignedDocuments().size());
		
		assertEquals("test.zip", extract.getSignedDocuments().get(0).getName());		
	}
	
	@Test
	void extractSignedOpenDocument() {
		DSSDocument document = signDocument(openDocument);
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
		ASiCContent extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertTrue(Utils.isCollectionNotEmpty(extract.getManifestDocuments()));
		assertEquals(1, extract.getManifestDocuments().size());

		assertFalse(Utils.isCollectionNotEmpty(extract.getContainerDocuments()));
	
		assertNotNull(extract.getMimeTypeDocument());
		MimeType mimeType = ASiCUtils.getMimeType(extract.getMimeTypeDocument());
		assertEquals("application/vnd.oasis.opendocument.text",  mimeType.getMimeTypeString());

		assertNotNull(extract.getAsicContainer());
		
		assertTrue(Utils.isCollectionNotEmpty(extract.getSignatureDocuments()));
		assertEquals(1, extract.getSignatureDocuments().size());
		assertTrue(Utils.isCollectionNotEmpty(extract.getSignedDocuments()));
		assertEquals(12, extract.getSignedDocuments().size());
		
		checkDocuments(openDocument, document);
	}
	
	private DSSDocument signDocument(DSSDocument documentToSign) {
		
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		signatureParameters.setSignedPropertiesCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		return signedDocument;
	}
	
	private void checkDocuments(DSSDocument original, DSSDocument signed) {		
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(original);
		ASiCContent extractOriginal = extractor.extract();
		
		extractor = new ASiCWithXAdESContainerExtractor(signed);
		ASiCContent extractSigned = extractor.extract();
		
		assertEquals(0, extractOriginal.getContainerDocuments().size());
		assertEquals(0, extractSigned.getContainerDocuments().size());
		
		assertEquals(0, extractOriginal.getSignatureDocuments().size());
		assertEquals(1, extractSigned.getSignatureDocuments().size());
		
		assertEquals(extractOriginal.getSignedDocuments().size(), extractSigned.getSignedDocuments().size());
		
		List<String> fileNames = getSignedFilesNames(extractSigned.getSignedDocuments());		
		List<Digest> fileDigests = getSignedFilesDigests(extractSigned.getSignedDocuments());

		for (DSSDocument doc : extractOriginal.getSignedDocuments()) {
			assertTrue(fileNames.contains(doc.getName()));
			assertTrue(fileDigests.contains(new Digest(DigestAlgorithm.SHA256, doc.getDigestValue(DigestAlgorithm.SHA256))));
		}	
	}
	
	private List<String> getSignedFilesNames(List<DSSDocument> files) {
		List<String> fileNames = new ArrayList<>();
		for (DSSDocument doc: files) {
			fileNames.add(doc.getName());
		}
		return fileNames;
	}
	
	private List<Digest> getSignedFilesDigests(List<DSSDocument> files) {
		List<Digest> fileDigests = new ArrayList<>();
		for (DSSDocument doc : files) {
			fileDigests.add(new Digest(DigestAlgorithm.SHA256, doc.getDigestValue(DigestAlgorithm.SHA256)));
		}
		return fileDigests;
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getGoodTsa();
	}

}
