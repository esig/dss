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
package eu.europa.esig.dss.xades.timestamp;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

class UnsupportedOperationTimestampXAdESTest extends PKIFactoryAccess {

	@Test
	void unsupportedOperationException() {
		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeTypeEnum.TEXT);
		DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeTypeEnum.TEXT);
		List<DSSDocument> docs = Arrays.asList(documentToSign, documentToSign2);

		XAdESTimestampParameters timestampParameters = new XAdESTimestampParameters();
		assertThrows(UnsupportedOperationException.class, () -> service.timestamp(documentToSign, timestampParameters));
		assertThrows(UnsupportedOperationException.class, () -> service.timestamp(docs, timestampParameters));
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
