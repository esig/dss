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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;

public class PdfBoxObjectFactoryTest {

	private static final String PDFBOX_SIGNATURE_SERVICE = "PdfBoxSignatureService";

	@Test
	public void testSystemProperty() {
		PDFSignatureService signatureService = PdfObjFactory.newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(PDFBOX_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
		PDFTimestampService timestampService = PdfObjFactory.newTimestampSignatureService();
		assertNotNull(timestampService);
		assertEquals(PDFBOX_SIGNATURE_SERVICE, timestampService.getClass().getSimpleName());
	}

	@Test
	public void testRuntimeChange() {
		PdfObjFactory.setInstance(new EmptyPdfObjectFactory());
		PDFSignatureService signatureService = PdfObjFactory.newPAdESSignatureService();
		assertNull(signatureService);
		PDFTimestampService timestampService = PdfObjFactory.newTimestampSignatureService();
		assertNull(timestampService);

		PdfObjFactory.setInstance(new PdfBoxDefaultObjectFactory());

		signatureService = PdfObjFactory.newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(PDFBOX_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
	}

	private class EmptyPdfObjectFactory implements IPdfObjFactory {

		@Override
		public PDFSignatureService newPAdESSignatureService() {
			return null;
		}

		@Override
		public PDFTimestampService newTimestampSignatureService() {
			return null;
		}

	}

}
