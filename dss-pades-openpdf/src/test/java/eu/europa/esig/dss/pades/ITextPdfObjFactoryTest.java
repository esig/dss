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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfPermissionsChecker;
import eu.europa.esig.dss.pdf.PdfSignatureFieldPositionChecker;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.openpdf.ITextDefaultPdfObjFactory;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ITextPdfObjFactoryTest {

	private static final String ITEXT_SIGNATURE_SERVICE = "ITextPDFSignatureService";

	@Test
	public void testSystemProperty() {
		IPdfObjFactory ipof = new ServiceLoaderPdfObjFactory();

		PDFSignatureService signatureService = ipof.newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(ITEXT_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
		PDFSignatureService timestampService = ipof.newSignatureTimestampService();
		assertNotNull(timestampService);
		assertEquals(ITEXT_SIGNATURE_SERVICE, timestampService.getClass().getSimpleName());
	}

	@Test
	public void testRuntimeChange() {

		IPdfObjFactory ipof = new EmptyPdfObjectFactory();

		PDFSignatureService signatureService = ipof.newPAdESSignatureService();
		assertNull(signatureService);
		PDFSignatureService timestampService = ipof.newSignatureTimestampService();
		assertNull(timestampService);

		ipof = new ITextDefaultPdfObjFactory();

		signatureService = ipof.newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(ITEXT_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
	}

	private static class EmptyPdfObjectFactory implements IPdfObjFactory {

		@Override
		public PDFSignatureService newPAdESSignatureService() {
			return null;
		}

		@Override
		public PDFSignatureService newContentTimestampService() {
			return null;
		}

		@Override
		public PDFSignatureService newSignatureTimestampService() {
			return null;
		}

		@Override
		public PDFSignatureService newArchiveTimestampService() {
			return null;
		}

		@Override
		public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
			// do nothing
		}

		@Override
		public void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder) {
			// do nothing
		}

		@Override
		public void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder) {
			// do nothing
		}

		@Override
		public void setPdfPermissionsChecker(PdfPermissionsChecker pdfPermissionsChecker) {
			// do nothing
		}

		@Override
		public void setPdfSignatureFieldPositionChecker(PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker) {
			// do nothing
		}

	}

}
