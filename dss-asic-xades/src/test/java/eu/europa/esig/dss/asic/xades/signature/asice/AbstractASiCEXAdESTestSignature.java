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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCTestSignature;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.validation.ASiCEWithXAdESManifestParser;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCEXAdESTestSignature extends
		AbstractASiCTestSignature<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.ASICE;
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
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		ASiCWithXAdESContainerExtractor containerExtractor = new ASiCWithXAdESContainerExtractor(new InMemoryDocument(byteArray));
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
		assertEquals(1, manifestDocuments.size());

		for (DSSDocument signatureDocument : signatures) {
			ManifestFile manifestFile = new ASiCEWithXAdESManifestParser(signatureDocument, manifestDocuments.get(0)).getManifest();
			assertNotNull(manifestFile);

			assertNotNull(manifestFile.getFilename());
			assertNotNull(manifestFile.getSignatureFilename());
			assertTrue(Utils.isCollectionNotEmpty(manifestFile.getEntries()));
			for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
				assertNotNull(manifestEntry.getFileName());
				assertNotNull(manifestEntry.getMimeType());
				assertTrue(Utils.isStringNotEmpty(manifestEntry.getMimeType().getMimeTypeString()));
			}
		}
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNotNull(diagnosticData.getContainerInfo());
		assertEquals(ASiCContainerType.ASiC_E, diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
	}

}
