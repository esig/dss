package eu.europa.esig.dss.jades.validation;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class JWSValidationTest {

	@Test
	public void test() {
		// HMAC
		// DSSDocument jws = new
		// InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());

		// http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-39#appendix-A.3
		String jwsString = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

		DSSDocument jws = new InMemoryDocument(jwsString.getBytes());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(jws);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();
		// TODO
		 UnmarshallingTester.unmarshallXmlReports(reports);
	}

}
