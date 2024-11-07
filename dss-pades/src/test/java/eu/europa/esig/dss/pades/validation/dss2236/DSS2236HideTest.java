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
package eu.europa.esig.dss.pades.validation.dss2236;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class DSS2236HideTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2236/hide.pdf"));
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();

		DefaultPdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();
		pdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(1);
		pdfObjFactory.setPdfDifferencesFinder(pdfDifferencesFinder);

		DefaultPdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();
		pdfObjectModificationsFinder.setMaximumObjectVerificationDeepness(10);
		pdfObjFactory.setPdfObjectModificationsFinder(pdfObjectModificationsFinder);

		PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
		validator.setPdfObjFactory(pdfObjFactory);

		return validator;
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		PDFRevisionWrapper pdfRevision = signature.getPDFRevision();
		assertTrue(pdfRevision.arePdfObjectModificationsDetected());

		assertTrue(Utils.isCollectionNotEmpty(pdfRevision.getPdfUndefinedChanges()));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isSigningCertificateIdentified());
	}

}
