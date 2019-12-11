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
package eu.europa.esig.dss.asic.cades.timestamp.asics;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCSTimestampOneFileTest extends PKIFactoryAccess {

	@Test
	public void test() throws IOException {
		DocumentSignatureService<ASiCWithCAdESSignatureParameters> service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

		DSSDocument archiveWithTimestamp = service.timestamp(documentToSign, signatureParameters);
		assertNotNull(archiveWithTimestamp);

		archiveWithTimestamp.save("target/test.asics");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(archiveWithTimestamp);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		assertNotNull(reports);

	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
