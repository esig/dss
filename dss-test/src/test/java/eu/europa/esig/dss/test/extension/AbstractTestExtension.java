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
package eu.europa.esig.dss.test.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.validation.reports.Reports;

public abstract class AbstractTestExtension<SP extends SerializableSignatureParameters, 
				TP extends SerializableTimestampParameters> extends AbstractPkiFactoryTestValidation<SP, TP> {

	protected abstract DSSDocument getOriginalDocument();

	protected abstract DSSDocument getSignedDocument(DSSDocument originalDoc);

	protected abstract SignatureLevel getOriginalSignatureLevel();

	protected abstract SignatureLevel getFinalSignatureLevel();

	protected abstract DocumentSignatureService<SP, TP> getSignatureServiceToSign();

	protected abstract DocumentSignatureService<SP, TP> getSignatureServiceToExtend();

	protected abstract TSPSource getUsedTSPSourceAtSignatureTime();

	protected abstract TSPSource getUsedTSPSourceAtExtensionTime();

	@Test
	public void extendAndVerify() throws Exception {
		DSSDocument originalDocument = getOriginalDocument();

		DSSDocument signedDocument = getSignedDocument(originalDocument);

		String signedFilePath = "target/" + signedDocument.getName();
		signedDocument.save(signedFilePath);

		assertNotNull(signedDocument);
		assertNotNull(signedDocument.getMimeType());
		assertNotNull(DSSUtils.toByteArray(signedDocument));
		assertNotNull(signedDocument.getName());
		
		Reports reports = verify(signedDocument);
		checkOriginalLevel(reports.getDiagnosticData());

		DSSDocument extendedDocument = extendSignature(signedDocument);

		String extendedFilePath = "target/" + extendedDocument.getName();
		extendedDocument.save(extendedFilePath);

		compare(signedDocument, extendedDocument);

		assertNotNull(extendedDocument);
		assertNotNull(extendedDocument.getMimeType());
		assertNotNull(DSSUtils.toByteArray(extendedDocument));
		assertNotNull(extendedDocument.getName());

		reports = verify(extendedDocument);
		checkFinalLevel(reports.getDiagnosticData());
		checkTLevelAndValid(reports.getDiagnosticData());

		File fileToBeDeleted;
		deleteOriginalFile(originalDocument);

		fileToBeDeleted = new File(signedFilePath);
		assertTrue(fileToBeDeleted.exists());
		assertTrue(fileToBeDeleted.delete(), "Cannot delete signed document (IO error)");
		assertFalse(fileToBeDeleted.exists());

		fileToBeDeleted = new File(extendedFilePath);
		assertTrue(fileToBeDeleted.exists());
		assertTrue(fileToBeDeleted.delete(), "Cannot delete extended document (IO error)");
		assertFalse(fileToBeDeleted.exists());
	}

	protected void deleteOriginalFile(DSSDocument originalDocument) {
		File fileToBeDeleted = new File(originalDocument.getAbsolutePath());
		assertTrue(fileToBeDeleted.exists());
		assertTrue(fileToBeDeleted.delete(), "Cannot delete original document (IO error)");
		assertFalse(fileToBeDeleted.exists());
	}

	protected void compare(DSSDocument signedDocument, DSSDocument extendedDocument) {
	}

	protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
		SP extensionParameters = getExtensionParameters();
		DocumentSignatureService<SP, TP> service = getSignatureServiceToExtend();

		DSSDocument extendedDocument = service.extendDocument(signedDocument, extensionParameters);
		assertNotNull(extendedDocument);

		// extendedDocument.save("target/pdf.pdf");

		return extendedDocument;
	}

	protected abstract SP getSignatureParameters();

	protected abstract SP getExtensionParameters();

	protected void checkOriginalLevel(DiagnosticData diagnosticData) {
		assertEquals(getOriginalSignatureLevel(), diagnosticData.getFirstSignatureFormat());
	}

	protected void checkFinalLevel(DiagnosticData diagnosticData) {
		assertEquals(getFinalSignatureLevel(), diagnosticData.getFirstSignatureFormat());
	}
	
	protected void checkTLevelAndValid(DiagnosticData diagnosticData) {
        assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
        assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

	protected void onDocumentSigned(DSSDocument signedDocument) {
		// do nothing by default
	}

	protected void onDocumentExtended(DSSDocument extendedDocument) {
		// do nothing by default
	}

}
