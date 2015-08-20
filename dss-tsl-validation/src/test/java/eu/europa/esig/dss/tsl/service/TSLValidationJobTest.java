package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TSLValidationJobTest {

	@Test
	public void test() {

		TSLRepository repository = new TSLRepository();
		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
		KeyStoreCertificateSource dssKeyStore = new KeyStoreCertificateSource(new File("src/test/resources/keystore.jks"), "dss-password");
		job.setDssKeyStore(dssKeyStore);
		job.setRepository(repository);

		job.refresh();

		spain = repository.getByCountry("ES");
		assertNotNull(spain);

		boolean foundExternalCertificates = false;
		TSLParserResult parseResult = spain.getParseResult();
		List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				if (tslService.getCertificateUrls().size() >0){
					foundExternalCertificates = true;
					break;
				}
			}
		}
		assertTrue(foundExternalCertificates);
	}

}
