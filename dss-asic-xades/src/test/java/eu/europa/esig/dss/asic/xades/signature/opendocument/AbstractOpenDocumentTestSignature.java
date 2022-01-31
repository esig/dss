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
package eu.europa.esig.dss.asic.xades.signature.opendocument;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractOpenDocumentTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

	private DSSDocument fileToTest;
	
	private static Stream<Arguments> data() {
		File folder = new File("src/test/resources/opendocument");
		Collection<File> listFiles = Utils.listFiles(folder,
				new String[] { "odp" }, true);
		

		List<Arguments> args = new ArrayList<>();
		for (File file : listFiles) {
			args.add(Arguments.of(new FileDocument(file)));
		}
		return args.stream();
	}
	
	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void test(DSSDocument fileToTest) {
		this.fileToTest = fileToTest;

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return fileToTest;
	}
	
	@Override
	protected MimeType getExpectedMime() {
		return getDocumentToSign().getMimeType();
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		return SignatureLevel.XAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNotNull(diagnosticData.getContainerInfo());
		assertNotNull(diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(getOriginalDocuments().get(0));
		ASiCContent extractOriginal = extractor.extract();
		
		AbstractASiCContainerValidator asicValidator = (AbstractASiCContainerValidator) validator;
		List<DSSDocument> signedDocuments = asicValidator.getSignedDocuments();
		
		List<String> fileNames = getSignedFilesNames(signedDocuments);		
		List<String> fileDigests = getSignedFilesDigests(signedDocuments);

		for (DSSDocument doc : extractOriginal.getSignedDocuments()) {
			assertTrue(fileNames.contains(doc.getName()));
			assertTrue(fileDigests.contains(doc.getDigest(DigestAlgorithm.SHA256)));
		}	
		
		verifySignatureFileName(asicValidator.getSignatureDocuments());
	}
	
	private List<String> getSignedFilesNames(List<DSSDocument> files) {
		List<String> fileNames = new ArrayList<>();
		for(DSSDocument doc: files) {
			fileNames.add(doc.getName());
		}
		return fileNames;
	}
	
	private List<String> getSignedFilesDigests(List<DSSDocument> files) {
		List<String> fileDigests = new ArrayList<>();
		for(DSSDocument doc: files) {
			fileDigests.add(doc.getDigest(DigestAlgorithm.SHA256));
		}
		return fileDigests;
	}
	
	public void verifySignatureFileName(List<DSSDocument> signatureFiles) {
		assertEquals(1, signatureFiles.size());
		DSSDocument signature = signatureFiles.get(0);
		assertEquals("META-INF/documentsignatures.xml", signature.getName());
	}

}
