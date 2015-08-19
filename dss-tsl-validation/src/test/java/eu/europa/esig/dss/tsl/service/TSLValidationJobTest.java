package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TSLValidationJobTest {

	@Test
	public void test() {

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
		KeyStoreCertificateSource dssKeyStore = new KeyStoreCertificateSource(new File("src/test/resources/keystore.jks"), "dss-password");
		job.setDssKeyStore(dssKeyStore);
		TSLRepository repository = new TSLRepository();
		job.setRepository(repository);

		job.refresh();

		TSLValidationModel belgium = repository.getByCountry("BE");

		assertNotNull(belgium);
	}

}
