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
package eu.europa.esig.dss.pades.timestamp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.Test;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class PDFTimestampServiceTest extends PKIFactoryAccess {

	@Test
	@SuppressWarnings("unchecked")
	public void timestampAlone() throws IOException {
		PDFTimestampService pdfTimestampService = PdfObjFactory.newTimestampSignatureService();

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();

		// The following parameters MUST be ignored (ETSI EN 319 142-1 V1.1.1, section 5.4.3)
		parameters.setLocation("LOCATION");
		parameters.setSignatureName("TEST TIMESTAMP");
		parameters.setReason("REASON");
		parameters.setContactInfo("CONTACT INFO");

		DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		DSSDocument timestamped = pdfTimestampService.timestamp(document, parameters, getGoodTsa());
		
		try (InputStream is = timestamped.openStream(); PdfReader reader = new PdfReader(is)) {
			AcroFields af = reader.getAcroFields();

			List<String> names = af.getSignatureNames();
			assertEquals(1, names.size());
			
			String first = names.get(0);
			
			PdfDictionary signatureDictionary = af.getSignatureDictionary(first);
			assertNull(signatureDictionary.get(PdfName.REASON));
			assertNull(signatureDictionary.get(PdfName.NAME));
			assertNull(signatureDictionary.get(PdfName.LOCATION));
			assertNull(signatureDictionary.get(PdfName.CONTACTINFO));
			assertNull(signatureDictionary.get(PdfName.M));
		}
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
