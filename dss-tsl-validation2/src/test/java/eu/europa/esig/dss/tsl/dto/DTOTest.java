package eu.europa.esig.dss.tsl.dto;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.tsl.dto.TrustService.TrustServiceBuilder;
import eu.europa.esig.dss.tsl.dto.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.tsl.dto.builder.TrustServiceProviderBuilder;
import eu.europa.esig.dss.tsl.dto.condition.CompositeCondition;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.enums.Assert;

public class DTOTest {
	
	private static CertificateToken cert;
	
	@BeforeAll
	public static void init() {
		cert = DSSUtils.loadCertificateFromBase64EncodedString("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");
	}
	
	@Test
	public void conditionForQualifiersTest() {
		ConditionForQualifiers conditionForQualifiers = getConditionForQualifiers();
		assertTrue(conditionForQualifiers.getCondition().check(cert));
		assertEquals(2, conditionForQualifiers.getQualifiers().size());
		assertEquals("First", conditionForQualifiers.getQualifiers().get(0));
	}
	
	private ConditionForQualifiers getConditionForQualifiers() {
		return new ConditionForQualifiers(new CompositeCondition(Assert.ALL), Arrays.asList("First", "Second"));
	}
	
	@Test
	public void otherTSLPointerDTOTest() {
		OtherTSLPointerDTO otherTSLPointerDTO = new OtherTSLPointerDTO("CZ", Arrays.asList(cert));
		assertEquals("CZ", otherTSLPointerDTO.getLocation());
		assertEquals(1, otherTSLPointerDTO.getCertificates().size());
		assertEquals(cert, otherTSLPointerDTO.getCertificates().get(0));
	}
	
	@Test
	public void trustServiceProviderBuilder() {
		TrustServiceProviderBuilder builder = new TrustServiceProviderBuilder();
		
		Map<String, List<String>> names = new HashMap<String, List<String>>();
		names.put("CZ", Arrays.asList("TSP1", "TSP2"));
		builder.setNames(names);
		
		Map<String, List<String>> tradeNames = new HashMap<String, List<String>>();
		tradeNames.put("CZ", Arrays.asList("TSPTradeName1", "TSPTradeName2"));
		builder.setTradeNames(tradeNames);
		
		builder.setRegistrationIdentifiers(Arrays.asList("VAT 154764", "PAS 4898464"));

		Map<String, String> postalAddresses = new HashMap<String, String>();
		postalAddresses.put("CZ", "Prague, Second Street 15");
		builder.setPostalAddresses(postalAddresses);
		
		Map<String, List<String>> electronicAddresses = new HashMap<String, List<String>>();
		electronicAddresses.put("CZ", Arrays.asList("address@gmail.com", "mail@mail.com"));
		builder.setElectronicAddresses(electronicAddresses);

		Map<String, String> information = new HashMap<String, String>();
		information.put("CZ", "Information");
		builder.setInformation(information);
		
		List<TrustService> trustServices = new ArrayList<TrustService>();
		
		TrustServiceBuilder trustServiceBuilder = new TrustService.TrustServiceBuilder();
		trustServiceBuilder.setCertificates(Arrays.asList(cert));
		
		TrustServiceStatusAndInformationExtensionsBuilder statusBuilder = new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder();
		statusBuilder.setNames(names);
		statusBuilder.setStartDate(new Date());
		statusBuilder.setEndDate(new GregorianCalendar(2050, 1, 1).getTime());
		statusBuilder.setStatus("withdrawn");
		statusBuilder.setType("sig");
		statusBuilder.setConditionsForQualifiers(Arrays.asList(getConditionForQualifiers()));
		statusBuilder.setAdditionalServiceInfoUris(Arrays.asList("http://site.cz.gov"));
		statusBuilder.setServiceSupplyPoints(Arrays.asList("http://service-supply.cz.gov"));
		statusBuilder.setExpiredCertsRevocationInfo(new GregorianCalendar(2030, 1, 1).getTime());
		TrustServiceStatusAndInformationExtensions status = statusBuilder.build();
		
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> timeDependentValues = new TimeDependentValues<>(Arrays.asList(status));
		trustServiceBuilder.setStatusAndInformationExtensions(timeDependentValues);
		
		trustServices.add(trustServiceBuilder.build());
		builder.setServices(trustServices);
		
		TrustServiceProvider trustServiceProvider = builder.build();
		
		Map<String, List<String>> tspNames = trustServiceProvider.getNames();
		assertTrue(Utils.isMapNotEmpty(tspNames));
		assertTrue(Utils.isCollectionNotEmpty(tspNames.get("CZ")));
		assertThrows(UnsupportedOperationException.class, () -> tspNames.get("CZ").add("name"));
		assertThrows(UnsupportedOperationException.class, () -> tspNames.put("LU", Arrays.asList("Lux")));
		
		Map<String, List<String>> tspTradeNames = trustServiceProvider.getTradeNames();
		assertTrue(Utils.isMapNotEmpty(tspTradeNames));
		assertTrue(Utils.isCollectionNotEmpty(tspTradeNames.get("CZ")));
		assertThrows(UnsupportedOperationException.class, () -> tspTradeNames.get("CZ").add("name"));
		assertThrows(UnsupportedOperationException.class, () -> tspTradeNames.put("LU", Arrays.asList("Lux")));
		
		List<String> tspRegistrationIdentifiers = trustServiceProvider.getRegistrationIdentifiers();
		assertTrue(Utils.isCollectionNotEmpty(tspRegistrationIdentifiers));
		assertThrows(UnsupportedOperationException.class, () -> tspRegistrationIdentifiers.add("id"));
		
		Map<String, String> tspPostalAddresses = trustServiceProvider.getPostalAddresses();
		assertTrue(Utils.isMapNotEmpty(tspPostalAddresses));
		assertThrows(UnsupportedOperationException.class, () -> tspPostalAddresses.put("LU", "Kehlen"));
		
		Map<String, String> tspInformation = trustServiceProvider.getInformation();
		assertTrue(Utils.isMapNotEmpty(tspInformation));
		assertThrows(UnsupportedOperationException.class, () -> tspInformation.put("LU", "Nowina"));
		
		List<TrustService> services = trustServiceProvider.getServices();
		assertTrue(Utils.isCollectionNotEmpty(services));
		assertThrows(UnsupportedOperationException.class, () -> services.add(new TrustService.TrustServiceBuilder().build()));
		assertEquals(1, services.size());
		
		TrustService trustService = services.get(0);
		
		List<CertificateToken> certificates = trustService.getCertificates();
		assertTrue(Utils.isCollectionNotEmpty(certificates));
		assertThrows(UnsupportedOperationException.class, () -> certificates.add(cert));
		assertEquals(cert, certificates.get(0));
		
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> statuses = trustService.getStatusAndInformationExtensions();
		assertNotNull(statuses);
		
		TrustServiceStatusAndInformationExtensions latest = statuses.getLatest();
		assertNotNull(latest);
		assertNotNull(latest.getStartDate());
		assertNotNull(latest.getEndDate());
		assertNotNull(latest.getStatus());
		assertNotNull(latest.getType());
		assertNotNull(latest.getExpiredCertsRevocationInfo());
		
		Map<String, List<String>> latestStatusNames = latest.getNames();
		assertTrue(Utils.isMapNotEmpty(latestStatusNames));
		assertTrue(Utils.isCollectionNotEmpty(latestStatusNames.get("CZ")));
		assertThrows(UnsupportedOperationException.class, () -> latestStatusNames.get("CZ").add("name"));
		assertThrows(UnsupportedOperationException.class, () -> latestStatusNames.put("LU", Arrays.asList("Lux")));
		
		List<ConditionForQualifiers> latestConditionsForQualifiers = latest.getConditionsForQualifiers();
		assertTrue(Utils.isCollectionNotEmpty(latestConditionsForQualifiers));
		assertThrows(UnsupportedOperationException.class, () -> latestConditionsForQualifiers.add(getConditionForQualifiers()));
		
		List<String> latestAdditionalServiceInfoUris = latest.getAdditionalServiceInfoUris();
		assertTrue(Utils.isCollectionNotEmpty(latestAdditionalServiceInfoUris));
		assertThrows(UnsupportedOperationException.class, () -> latestAdditionalServiceInfoUris.add("uri"));
		
		List<String> latestServiceSupplyPoints = latest.getServiceSupplyPoints();
		assertTrue(Utils.isCollectionNotEmpty(latestServiceSupplyPoints));
		assertThrows(UnsupportedOperationException.class, () -> latestServiceSupplyPoints.add("1.2.3"));
		
	}
	
	@Test
	public void emptyTrustServiceProviderBuilderTest() {
		TrustServiceProviderBuilder builder = new TrustServiceProviderBuilder();
		TrustServiceProvider trustServiceProvider = builder.build();
		assertNotNull(trustServiceProvider.getElectronicAddresses());
		assertNotNull(trustServiceProvider.getInformation());
		assertNotNull(trustServiceProvider.getNames());
		assertNotNull(trustServiceProvider.getPostalAddresses());
		assertNotNull(trustServiceProvider.getRegistrationIdentifiers());
		assertNotNull(trustServiceProvider.getServices());
		assertNotNull(trustServiceProvider.getTradeNames());
	}

}
