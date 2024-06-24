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
package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.UnmarshallingTester;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class JWSValidationTest {

	// No key in the samples

	@Test
	public void testA2() {
		// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-39#appendix-A.2

		String jwsString = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
		DSSDocument jws = new InMemoryDocument(jwsString.getBytes());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(jws);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

//		reports.print();
		UnmarshallingTester.unmarshallXmlReports(reports);
	}

	@Test
	public void testA3() {
		// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-39#appendix-A.3

		String jwsString = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
		DSSDocument jws = new InMemoryDocument(jwsString.getBytes());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(jws);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();
		UnmarshallingTester.unmarshallXmlReports(reports);
	}

	@Test
	public void testA6() {
		// https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-39#appendix-A.6

		String jwsString = "{\"payload\":\"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\",\"signatures\":[{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"header\":{\"kid\":\"2010-12-29\"},\"signature\":\"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw\"},{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"header\":{\"kid\":\"e9bc097a-ce51-4036-9562-d2ade882db0d\"},\"signature\":\"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q\"}]}";
		DSSDocument jws = new InMemoryDocument(jwsString.getBytes());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(jws);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		UnmarshallingTester.unmarshallXmlReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		for (SignatureWrapper signatureWrapper : signatures) {
			assertEquals(SignatureLevel.JSON_NOT_ETSI, signatureWrapper.getSignatureFormat());
		}
	}

	@Test
	public void testJSONSerializationNoSignature() {
		String jwsString = "{\"hello\":\"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ\"}";
		DSSDocument jws = new InMemoryDocument(jwsString.getBytes());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(jws);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		UnmarshallingTester.unmarshallXmlReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(0, diagnosticData.getSignatures().size());
	}

}
