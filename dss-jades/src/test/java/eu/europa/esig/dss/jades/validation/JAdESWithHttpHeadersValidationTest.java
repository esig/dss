package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jades.HTTPHeaderDocument;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class JAdESWithHttpHeadersValidationTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		String jws = "eyJiNjQiOmZhbHNlLCJ4NXQjUzI1NiI6ImR5dFBwU2tKWXpoVGRQWFNXUDdqaFhnRzRrQ09XSVdHaWV" + 
				"zZHprdk5Melk9IiwiY3JpdCI6WyJzaWdUIiwic2lnRCIsImI2NCJdLCJzaWdUIjoiMjAyMC0wNC0yOV" + 
				"QxMjoyODoyOVoiLCJzaWdEIjp7InBhcnMiOlsiKHJlcXVlc3QtdGFyZ2V0KSIsIkNvbnRlbnQtVHlwZ" + 
				"SIsIlBTVS1JUC1BZGRyZXNzIiwiUFNVLUdFTy1Mb2NhdGlvbiIsIkRpZ2VzdCJdLCJtSWQiOiJodHRw" + 
				"Oi8vdXJpLmV0c2kub3JnLzE5MTgyL0h0dHBIZWFkZXJzIn0sImFsZyI6IlJTMjU2In0..oIQPqsAkfE" + 
				"3RiPKNHXVtut2KMQjrSX2rxaFgG78ULHbgDKdZqaTR0KagWV4Dlap5wif0cl45PTFRAI8Hpep02YCji" + 
				"qIc1vpxyXMzWv52JG68_ITGXwrXZ2I2f46YmoeWEKtQwCHrslSXDXywdwuw0lHTEx04BO6WMt0Zy6ys" + 
				"eGj7gMfseEJhw4UO0o_aAIJtlHv2wQo8yeiKzWuE4dY1TBGny4CmfYWHWi4IR2IGDH_bJjzzR7FUTJD" + 
				"rdOTk55GxJMaXyGeK3bViHgcO57yH9xx07hvWWebmhuDmnMOsbXxlRFQnQ7s5xpDSrpRlEHDgfcOxKr" +
				"PB6dWGeSyWbJA";
		return new InMemoryDocument(jws.getBytes());
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(new HTTPHeaderDocument("(request-target)", 
				"post https://api.testbank.com/v1/payments/sepa-credittransfers"));
		detachedContents.add(new HTTPHeaderDocument("Content-Type", "application/json"));
		detachedContents.add(new HTTPHeaderDocument("X-Request-ID", "99391c7e-ad88-49ec-a2ad-99ddcb1f7721"));
		detachedContents.add(new HTTPHeaderDocument("PSU-IP-Address", "192.168.8.78"));
		detachedContents.add(new HTTPHeaderDocument("PSU-GEO-Location", "GEO:52.506931,13.144558"));
		detachedContents.add(new HTTPHeaderDocument("PSU-User-Agent", 
				"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0"));
		detachedContents.add(new HTTPHeaderDocument("Date", "Fri, 3 Apr 2020 16:38:37 GMT"));
		detachedContents.add(new HTTPHeaderDocument("Digest", "SHA-256=+xeh7JAayYPh8K13UnQCBBcniZzsyat+KDiuy8aZYdI="));
		return detachedContents;
	}

}
