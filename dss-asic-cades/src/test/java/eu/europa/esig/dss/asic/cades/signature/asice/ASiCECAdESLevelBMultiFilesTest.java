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

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.junit.jupiter.api.BeforeEach;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCECAdESLevelBMultiFilesTest extends AbstractASiCEWithCAdESMultipleDocumentsTestSignature {

	private ASiCWithCAdESService service;
	private ASiCWithCAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentsToSign = new ArrayList<>();

	@BeforeEach
	public void init() throws Exception {
		service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT));
		documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT));
		documentsToSign.add(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "emptyByteArray"));

		signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		TimestampToken contentTimestamp = service.getContentTimestamp(documentsToSign, signatureParameters);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));
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
		assertEquals(1, manifestDocuments.size());
		String manifestFilename = manifestDocuments.get(0).getName();
		assertTrue(manifestFilename.startsWith("META-INF/ASiCManifest"));
		assertTrue(manifestFilename.endsWith(".xml"));

		List<DSSDocument> signedDocuments = extract.getSignedDocuments();
		assertEquals(3, signedDocuments.size());

		DSSDocument mimeTypeDocument = extract.getMimeTypeDocument();

		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		try {
			assertEquals(MimeTypeEnum.ASICE.getMimeTypeString(), new String(mimeTypeContent, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail(e.getMessage());
		}
	}
	
	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(4, digestMatchers.size());
		int manifestEntriesCounter = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.MANIFEST_ENTRY.equals(digestMatcher.getType())) {
				manifestEntriesCounter++;
			}
		}
		List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
		assertEquals(1, manifestFiles.size());
		List<String> entries = manifestFiles.get(0).getEntries();
		assertNotNull(entries);
		assertEquals(entries.size(), manifestEntriesCounter);
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(1, signatureIdList.size());

		SignatureWrapper signature = diagnosticData.getSignatureById(signatureIdList.get(0));
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertEquals(4, signatureScopes.size());
		for (XmlSignatureScope signatureScope : signatureScopes) {
			assertEquals(SignatureScopeType.FULL, signatureScope.getScope());
			assertNotNull(signatureScope.getName());
			assertNotNull(signatureScope.getDescription());
			XmlSignerData signerData = signatureScope.getSignerData();
			assertNotNull(signerData);
			assertNotNull(signerData.getId());
			assertNotNull(signerData.getReferencedName());
			assertNotNull(signerData.getDigestAlgoAndValue());
			assertNotNull(signerData.getDigestAlgoAndValue().getDigestMethod());
			assertNotNull(signerData.getDigestAlgoAndValue().getDigestValue());
		}
	}

	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		super.validateETSISignersDocument(signersDocument);

		DigestAlgAndValueType digestAlgoAndValue = getDigestAlgoAndValue(signersDocument);
		assertNotNull(digestAlgoAndValue);
		assertNotNull(digestAlgoAndValue.getDigestMethod());
		assertNotNull(digestAlgoAndValue.getDigestValue());

		List<ValidationObjectType> validationObjects = getValidationObjects(signersDocument);
		assertEquals(4, validationObjects.size());
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(MimeTypeEnum.XML, MimeType.fromMimeTypeString(signatureWrapper.getMimeType()));
		}
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		for (DSSDocument document : documentsToSign) {
			boolean found = false;
			for (DSSDocument retrievedDoc : retrievedDocuments) {
				if (Arrays.equals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(retrievedDoc))) {
					found = true;
				}
			}
			assertTrue(found);
		}
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentsToSign;
	}

	@Override
	protected MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
