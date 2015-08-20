package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TSLValidationJobTest {

	private static final Logger logger = LoggerFactory.getLogger(TSLValidationJobTest.class);

	private static final String LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
	private KeyStoreCertificateSource dssKeyStore;

	@Before
	public void init() {
		dssKeyStore = new KeyStoreCertificateSource(new File("src/test/resources/keystore.jks"), "dss-password");
	}

	@Test
	public void test() {

		TSLRepository repository = new TSLRepository();
		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setLotlUrl(LOTL_URL);
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
				if (CollectionUtils.isNotEmpty(tslService.getCertificateUrls())) {
					foundExternalCertificates = true;
					break;
				}
			}
		}
		assertTrue(foundExternalCertificates);
	}

	@Test
	public void testOnlyOneCountry() {

		TSLRepository repository = new TSLRepository();
		TSLValidationModel france = repository.getByCountry("FR");
		assertNull(france);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setLotlUrl(LOTL_URL);
		job.setDssKeyStore(dssKeyStore);
		job.setRepository(repository);
		List<String> filterTerritories = new ArrayList<String>();
		filterTerritories.add("FR");
		job.setFilterTerritories(filterTerritories);

		job.refresh();

		france = repository.getByCountry("FR");
		assertNotNull(france);

		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);
	}

	@Test
	public void testCache() {

		TSLRepository repository = new TSLRepository();

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setLotlUrl(LOTL_URL);
		job.setDssKeyStore(dssKeyStore);
		job.setRepository(repository);

		logger.info("***************** First load *****************");
		job.refresh();

		logger.info("***************** Second load *****************");
		job.refresh();
	}
}
