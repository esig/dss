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
package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCTestUtils;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCTestSignature<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters>
		extends AbstractPkiFactoryTestDocumentSignatureService<SP, TP> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		DSSDocument zipDocument = new InMemoryDocument(byteArray);
		assertTrue(ASiCUtils.isZip(zipDocument));
		ASiCTestUtils.verifyZipContainer(zipDocument);

		ASiCContent asicContent = getContainerExtractor(zipDocument).extract();
		checkExtractedContent(asicContent);
	}

	protected abstract AbstractASiCContainerExtractor getContainerExtractor(DSSDocument document);

	protected void checkExtractedContent(ASiCContent asicContent) {
		assertNotNull(asicContent);
		assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignedDocuments()));
		assertTrue(Utils.isCollectionNotEmpty(asicContent.getRootLevelSignedDocuments()));
		assertTrue(Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()));
		assertNotNull(asicContent.getMimeTypeDocument());
	}

	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNotNull(diagnosticData.getContainerInfo());
		assertNotNull(diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {

			SignatureWrapper signatureById = diagnosticData.getSignatureById(signatureId);
			if (signatureById.isCounterSignature()) {
				continue;
			}

			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));

			List<DSSDocument> originalDocuments = getOriginalDocuments();
			for (DSSDocument original : originalDocuments) {
				boolean found = false;
				if (ASiCContainerType.ASiC_S.equals(diagnosticData.getContainerType()) && originalDocuments.size() == 1 &&
						ASiCUtils.isZip(original)) {
					List<DSSDocument> archiveDocuments = ZipUtils.getInstance().extractContainerContent(original);
					if (Utils.isCollectionNotEmpty(archiveDocuments)) {
						found = true;
						for (DSSDocument archiveDocument : archiveDocuments) {
							found = documentPresent(archiveDocument, retrievedOriginalDocuments);
							if (!found) {
								break;
							}
						}
					}

				} else {
					found = documentPresent(original, retrievedOriginalDocuments);
				}

				assertTrue(found, "Unable to retrieve the original document " + original.getName());
			}
		}
	}

}
