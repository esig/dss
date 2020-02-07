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

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfReader;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class PDFTimestampServiceTest extends PKIFactoryAccess {

	@Test
	public void timestampAlone() throws IOException {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESTimestampParameters parameters = new PAdESTimestampParameters();

		DSSDocument document = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		DSSDocument timestamped = service.timestamp(document, parameters);

		try (InputStream is = timestamped.openStream(); PdfReader reader = new PdfReader(is)) {
			AcroFields af = reader.getAcroFields();

			List<String> names = af.getSignedFieldNames();
			assertEquals(1, names.size());

			String first = names.get(0);

			PdfDictionary signatureDictionary = af.getSignatureDictionary(first);
			assertNotNull(signatureDictionary);
		}
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
