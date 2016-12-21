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
package eu.europa.esig.dss.asic.signature.asice;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Before;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.validation.ASiCEWithXAdESManifestParser;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.signature.AbstractTestMultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class ASiCEXAdESMultiFilesLevelBTest extends AbstractTestMultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> {

	private MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns = new ArrayList<DSSDocument>();
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
		documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new ASiCWithXAdESService(certificateVerifier);
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		InMemoryDocument doc = new InMemoryDocument(byteArray);

		AbstractASiCContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(doc);
		ASiCExtractResult extract = extractor.extract();

		assertEquals(0, extract.getUnsupportedDocuments().size());

		List<DSSDocument> signatureDocuments = extract.getSignatureDocuments();
		assertEquals(1, signatureDocuments.size());
		String signatureFilename = signatureDocuments.get(0).getName();
		assertTrue(signatureFilename.startsWith("META-INF/signature"));
		assertTrue(signatureFilename.endsWith(".xml"));

		List<DSSDocument> manifestDocuments = extract.getManifestDocuments();
		assertEquals(1, manifestDocuments.size());
		String manifestFilename = manifestDocuments.get(0).getName();
		assertEquals("META-INF/manifest.xml", manifestFilename);

		ASiCEWithXAdESManifestParser parse = new ASiCEWithXAdESManifestParser(signatureDocuments.get(0), manifestDocuments.get(0));
		ManifestFile description = parse.getDescription();
		assertNotNull(description);
		assertNotNull(description.getFilename());
		assertNotNull(description.getSignatureFilename());
		assertTrue(Utils.isCollectionNotEmpty(description.getEntries()));

		List<DSSDocument> signedDocuments = extract.getSignedDocuments();
		assertEquals(2, signedDocuments.size());

		DSSDocument mimeTypeDocument = extract.getMimeTypeDocument();

		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		try {
			assertEquals(MimeType.ASICE.getMimeTypeString(), new String(mimeTypeContent, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail(e.getMessage());
		}
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(2, Utils.collectionSize(signatureScopes));
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.ASICE;
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
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

	@Override
	protected MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters> getService() {
		return service;
	}

}
