package eu.europa.esig.dss.cookbook.example.snippets;

import java.util.Arrays;

import eu.europa.esig.dss.tsl.OtherTrustedList;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class NonEUTrustedListLoadingSnippet {

	public void additionalTL() {

		// tag::demo[]

		TSLValidationJob job = new TSLValidationJob();
		// ...

		// Configuration to load the peruvian trusted list.
		// DSS requires the country code, the URL and allowed signing certificates
		OtherTrustedList peru = new OtherTrustedList();
		peru.setCountryCode("PE");
		peru.setUrl("https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml");
		peru.setTrustStore(getTrustStore());

		job.setOtherTrustedLists(Arrays.asList(peru));

		// tag::demo[]

	}

	private KeyStoreCertificateSource getTrustStore() {
		return null;
	}

}
