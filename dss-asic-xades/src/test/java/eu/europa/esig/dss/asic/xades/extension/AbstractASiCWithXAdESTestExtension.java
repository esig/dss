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
package eu.europa.esig.dss.asic.xades.extension;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.validation.ASiCEWithXAdESManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCWithXAdESTestExtension extends AbstractTestExtension<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getGoodTsa();
	}

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getAlternateGoodTsa();
	}

	@Override
	protected FileDocument getOriginalDocument() {
		File originalDoc = new File("target/original-" + UUID.randomUUID().toString() + ".bin");
		try (FileOutputStream fos = new FileOutputStream(originalDoc)) {
			fos.write("Hello world!".getBytes());
		} catch (IOException e) {
			throw new DSSException("Unable to create the original document", e);
		}
		return new FileDocument(originalDoc);
	}

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		ASiCWithXAdESSignatureParameters signatureParameters = getSignatureParameters();
		ASiCWithXAdESService service = getSignatureServiceToSign();

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		signatureParameters.aSiC().setContainerType(getContainerType());
		return signatureParameters;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
		ASiCWithXAdESSignatureParameters extensionParameters = new ASiCWithXAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.aSiC().setContainerType(getFinalContainerType());
		return extensionParameters;
	}

	protected abstract ASiCContainerType getContainerType();

	protected ASiCContainerType getFinalContainerType() {
		return getContainerType();
	}


	@Override
	protected void onDocumentSigned(DSSDocument signedDocument) {
		super.onDocumentSigned(signedDocument);

		onCreatedContainer(signedDocument);
	}

	@Override
	protected void onDocumentExtended(DSSDocument extendedDocument) {
		super.onDocumentExtended(extendedDocument);

		onCreatedContainer(extendedDocument);
	}

	protected void onCreatedContainer(DSSDocument container) {
		ASiCWithXAdESContainerExtractor containerExtractor = new ASiCWithXAdESContainerExtractor(container);
		ASiCContent asicContent = containerExtractor.extract();
		checkExtractedContent(asicContent);

		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		assertTrue(Utils.isCollectionNotEmpty(signatureDocuments));
		checkManifests(signatureDocuments, asicContent.getAllManifestDocuments());
	}

	protected void checkExtractedContent(ASiCContent asicContent) {
		assertNotNull(asicContent);
		assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()));
		assertNotNull(asicContent.getMimeTypeDocument());
		if (getSignatureParameters().aSiC().isZipComment()) {
			assertTrue(Utils.isStringNotBlank(asicContent.getZipComment()));
		}
	}

	protected void checkManifests(List<DSSDocument> signatures, List<DSSDocument> manifestDocuments) {
		if (ASiCContainerType.ASiC_E == getSignatureParameters().aSiC().getContainerType()) {
			assertEquals(1, manifestDocuments.size());

			for (DSSDocument signatureDocument : signatures) {
				ManifestFile manifestFile = new ASiCEWithXAdESManifestParser(signatureDocument, manifestDocuments.get(0)).getManifest();
				assertNotNull(manifestFile);

				assertNotNull(manifestFile.getFilename());
				assertNotNull(manifestFile.getSignatureFilename());
				assertTrue(Utils.isCollectionNotEmpty(manifestFile.getEntries()));
				for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
					assertNotNull(manifestEntry.getUri());
					assertNotNull(manifestEntry.getMimeType());
					assertTrue(Utils.isStringNotEmpty(manifestEntry.getMimeType().getMimeTypeString()));
				}
			}
		}
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		assertNotNull(containerInfo);

		assertEquals(getContainerType(), containerInfo.getContainerType());
	}

	@Override
	protected ASiCWithXAdESService getSignatureServiceToSign() {
		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		return service;
	}

	@Override
	protected ASiCWithXAdESService getSignatureServiceToExtend() {
		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtExtensionTime());
		return service;
	}

	@Override
	protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
		SignatureLevel signatureFormat = getFinalSignatureLevel();
		if (getSignatureParameters().isEn319132() &&
				(SignatureLevel.XAdES_BASELINE_B == signatureFormat ||
						SignatureLevel.XAdES_BASELINE_T == signatureFormat ||
						SignatureLevel.XAdES_BASELINE_LT == signatureFormat ||
						SignatureLevel.XAdES_BASELINE_LTA == signatureFormat)) {
			super.checkCertificateValuesEncapsulation(diagnosticData);
		}
		// skip for not BASELINE profiles
	}

	@Override
	protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
		SignatureLevel signatureFormat = getSignatureParameters().getSignatureLevel();
		if (getSignatureParameters().isEn319132() &&
				(SignatureLevel.XAdES_BASELINE_B == signatureFormat ||
						SignatureLevel.XAdES_BASELINE_T == signatureFormat ||
						SignatureLevel.XAdES_BASELINE_LT == signatureFormat ||
						SignatureLevel.XAdES_BASELINE_LTA == signatureFormat)) {
			super.checkRevocationDataEncapsulation(diagnosticData);
		}
		// skip for not BASELINE profiles
	}

	@Override
	protected void compare(DSSDocument signedDocument, DSSDocument extendedDocument) {
		// We check that all original files are present in the extended archive.
		// (signature are not renamed,...)

		List<String> filenames = ZipUtils.getInstance().extractEntryNames(signedDocument);
		List<String> extendedFilenames = ZipUtils.getInstance().extractEntryNames(extendedDocument);
		assertEquals(filenames.size(), extendedFilenames.size());

		for (String name : extendedFilenames) {
			assertTrue(filenames.contains(name));
		}

		for (String name : filenames) {
			assertTrue(extendedFilenames.contains(name));
		}
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNotNull(diagnosticData.getContainerInfo());
		assertNotNull(diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
