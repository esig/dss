package eu.europa.esig.dss.tsl.parsing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.dto.TrustService;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;
import eu.europa.esig.dss.tsl.dto.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.tsl.function.TrustServicePredicate;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

public class TLParsingTaskTest {

	private static XmlDownloadResult TL;

	@BeforeAll
	public static void init() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/ie-tl.xml")) {
			TL = new XmlDownloadResult("bla", Utils.toByteArray(fis), null);
		}
	}

	@Test
	public void testDefault() {
		TLParsingTask task = new TLParsingTask(new TLSource(), TL);
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(5, result.getVersion());
		assertEquals(18, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("IE", result.getTerritory());
		assertNull(result.getDistributionPoints());

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(3, trustServiceProviders.size());
		
		checkTSPs(trustServiceProviders);

		TrustServiceProvider postTrust = trustServiceProviders.get(0);
		assertEquals(1, postTrust.getServices().size());

		TrustServiceProvider adobe = trustServiceProviders.get(1);
		assertEquals(1, adobe.getServices().size());

		TrustServiceProvider trustPro = trustServiceProviders.get(2);
		assertEquals(2, trustPro.getServices().size());
	}

	private void checkTSPs(List<TrustServiceProvider> trustServiceProviders) {
		for (TrustServiceProvider tsp : trustServiceProviders) {

			assertNotNull(tsp.getNames());
			assertFalse(tsp.getNames().isEmpty());

			assertNotNull(tsp.getTradeNames());
			assertFalse(tsp.getTradeNames().isEmpty());

			assertNotNull(tsp.getRegistrationIdentifiers());
			assertFalse(tsp.getRegistrationIdentifiers().isEmpty());

			assertNotNull(tsp.getElectronicAddresses());
			assertFalse(tsp.getElectronicAddresses().isEmpty());

			assertNotNull(tsp.getPostalAddresses());
			assertFalse(tsp.getPostalAddresses().isEmpty());

			assertNotNull(tsp.getInformation());
			assertFalse(tsp.getInformation().isEmpty());

			assertNotNull(tsp.getServices());
			assertFalse(tsp.getServices().isEmpty());
			
			checkServices(tsp.getServices());
		}
	}

	private void checkServices(List<TrustService> services) {
		for (TrustService trustService : services) {
			assertNotNull(trustService.getCertificates());
			assertFalse(trustService.getCertificates().isEmpty());

			TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions = trustService.getStatusAndInformationExtensions();
			assertNotNull(statusAndInformationExtensions);

			TrustServiceStatusAndInformationExtensions latest = statusAndInformationExtensions.getLatest();
			assertNotNull(latest);

			assertNotNull(latest.getNames());
			assertFalse(latest.getNames().isEmpty());

			assertNotNull(latest.getStatus());
			assertNotNull(latest.getStartDate());
			assertNotNull(latest.getType());
		}
	}

	@Test
	public void testFilterAllTrustServiceProviders() {
		TLSource tlSource = new TLSource();
		tlSource.setTrustServiceProviderPredicate(new TrustServiceProviderPredicate() {

			@Override
			public boolean test(TSPType t) {
				return false;
			}
		});

		TLParsingTask task = new TLParsingTask(tlSource, TL);
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(0, result.getTrustServiceProviders().size());
	}

	@Test
	public void testFilterAllTrustServices() {
		TLSource tlSource = new TLSource();
		tlSource.setTrustServicePredicate(new TrustServicePredicate() {

			@Override
			public boolean test(TSPServiceType t) {
				return false;
			}

		});

		TLParsingTask task = new TLParsingTask(tlSource, TL);
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(0, result.getTrustServiceProviders().size());
	}

}
