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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.model.tsl.ConditionForQualifiers;
import eu.europa.esig.dss.model.tsl.TrustService;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.tsl.function.TrustServicePredicate;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TLParsingTaskTest {

	private static DSSDocument DE_TL;
	private static DSSDocument FI_V5;
	private static DSSDocument FI_V5_INVALID_XML_TL;
	private static DSSDocument FI_V5_SIG_CERT_V2_TL;
	private static DSSDocument FI_V6_TL;
	private static DSSDocument FI_V6_NO_SUPPLY_POINTS_TYPE_TL;
	private static DSSDocument FI_V6_SIG_CERT_TL;
	private static DSSDocument FR_TL;
	private static DSSDocument IE_TL;
	private static DSSDocument SK_TL;
	private static DSSDocument SK_1911;

	private static DSSDocument LOTL;
	private static DSSDocument LOTL_NOT_PARSEABLE;

	@BeforeAll
	static void init() throws IOException {
		DE_TL = new FileDocument("src/test/resources/de-tl.xml");
		FI_V5 = new FileDocument("src/test/resources/fi-v5.xml");
		FI_V5_INVALID_XML_TL = new FileDocument("src/test/resources/fi-v5-invalid.xml");
		FI_V5_SIG_CERT_V2_TL = new FileDocument("src/test/resources/fi-v5-sig-cert-v2.xml");
		FI_V6_TL = new FileDocument("src/test/resources/fi-v6.xml");
		FI_V6_NO_SUPPLY_POINTS_TYPE_TL = new FileDocument("src/test/resources/fi-v6-no-supply-points-type.xml");
		FI_V6_SIG_CERT_TL = new FileDocument("src/test/resources/fi-v6-sig-cert.xml");
		FR_TL = new FileDocument("src/test/resources/fr.xml");
		IE_TL = new FileDocument("src/test/resources/ie-tl.xml");
		SK_TL = new FileDocument("src/test/resources/sk-tl.xml");
		SK_1911 = new FileDocument("src/test/resources/tsl-sk-minimal-dss-1911.xml");

		LOTL = new FileDocument("src/test/resources/eu-lotl.xml");
		LOTL_NOT_PARSEABLE = new FileDocument("src/test/resources/eu-lotl-not-parseable.xml");
	}

	@Test
	void testIEDefault() {
		TLParsingTask task = new TLParsingTask(IE_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(5, result.getVersion());
		assertEquals(18, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("IE", result.getTerritory());
		assertTrue(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

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

	@Test
	void testSKDefault() {
		TLParsingTask task = new TLParsingTask(SK_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(5, result.getVersion());
		assertEquals(59, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("SK", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(6, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(27, nsa.getServices().size());

		TrustServiceProvider disig = trustServiceProviders.get(1);
		assertEquals(56, disig.getServices().size());

		TrustServiceProvider mil = trustServiceProviders.get(2);
		assertEquals(8, mil.getServices().size());
	}

	@Test
	void testFIv5() {
		TLParsingTask task = new TLParsingTask(FI_V5, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(5, result.getVersion());
		assertEquals(49, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("FI", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(1, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(19, nsa.getServices().size());
	}

	@Test
	void testFIv5InvalidXml() {
		TLParsingTask task = new TLParsingTask(FI_V5_INVALID_XML_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(5, result.getVersion());
		assertEquals(49, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("FI", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertFalse(Utils.isCollectionEmpty(result.getStructureValidation()));
		assertTrue(result.getStructureValidation().stream().anyMatch(r -> r.contains("ServiceSupplyPoint")));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(1, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(19, nsa.getServices().size());
	}

	@Test
	void testFIv5SigCertV2() {
		TLParsingTask task = new TLParsingTask(FI_V5_SIG_CERT_V2_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(5, result.getVersion());
		assertEquals(49, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("FI", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertFalse(Utils.isCollectionEmpty(result.getStructureValidation()));
		assertTrue(result.getStructureValidation().stream().anyMatch(r -> r.contains("SigningCertificateV2")));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(1, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(19, nsa.getServices().size());
	}

	@Test
	void testFIv6() {
		TLParsingTask task = new TLParsingTask(FI_V6_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(6, result.getVersion());
		assertEquals(49, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("FI", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(1, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(19, nsa.getServices().size());
	}

	@Test
	void testFIv6NoSupplyPointsType() {
		TLParsingTask task = new TLParsingTask(FI_V6_NO_SUPPLY_POINTS_TYPE_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(6, result.getVersion());
		assertEquals(49, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("FI", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(1, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(19, nsa.getServices().size());
	}

	@Test
	void testFIv6SigCertV2() {
		TLParsingTask task = new TLParsingTask(FI_V6_SIG_CERT_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(6, result.getVersion());
		assertEquals(49, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("FI", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertFalse(Utils.isCollectionEmpty(result.getStructureValidation()));
		assertTrue(result.getStructureValidation().stream().anyMatch(r -> r.contains("SigningCertificate")));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(1, trustServiceProviders.size());

		checkTSPs(trustServiceProviders);

		TrustServiceProvider nsa = trustServiceProviders.get(0);
		assertEquals(19, nsa.getServices().size());
	}

	@Test
	void testLOTL() {
		TLParsingTask task = new TLParsingTask(LOTL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(248, result.getSequenceNumber());
		assertEquals("EU", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		assertEquals(0, trustServiceProviders.size());
	}

	@Test
	void notParseable() {
		TLParsingTask task = new TLParsingTask(LOTL_NOT_PARSEABLE, new TLSource());
		DSSException exception = assertThrows(DSSException.class, () -> task.get());
		assertTrue(exception.getMessage().contains("Unable to parse binaries"));
	}

	private void checkTSPs(List<TrustServiceProvider> trustServiceProviders) {
		for (TrustServiceProvider tsp : trustServiceProviders) {

			assertNotNull(tsp.getNames());
			assertFalse(tsp.getNames().isEmpty());

			assertNotNull(tsp.getRegistrationIdentifiers());
			assertFalse(tsp.getRegistrationIdentifiers().isEmpty());

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
	void testFilterAllTrustServiceProviders() {
		TLSource tlSource = new TLSource();
		tlSource.setTrustServiceProviderPredicate(new TrustServiceProviderPredicate() {

			@Override
			public boolean test(TSPType t) {
				return false;
			}
		});

		TLParsingTask task = new TLParsingTask(IE_TL, tlSource);
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(0, result.getTrustServiceProviders().size());
	}

	@Test
	void testFilterAllTrustServices() {
		TLSource tlSource = new TLSource();
		tlSource.setTrustServicePredicate(new TrustServicePredicate() {

			@Override
			public boolean test(TSPServiceType t) {
				return false;
			}

		});

		TLParsingTask task = new TLParsingTask(IE_TL, tlSource);
		TLParsingResult result = task.get();
		assertNotNull(result);
		assertEquals(0, result.getTrustServiceProviders().size());
	}

	@Test
	void countCertificatesDE() throws Exception {
		TLParsingTask task = new TLParsingTask(DE_TL, new TLSource());
		TLParsingResult result = task.get();

		assertNotNull(result);
		assertEquals(4, result.getVersion());
		assertEquals(22, result.getSequenceNumber());
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals("DE", result.getTerritory());
		assertFalse(Utils.isCollectionEmpty(result.getDistributionPoints()));
		assertTrue(Utils.isCollectionEmpty(result.getStructureValidation()));

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);

		Set<CertificateToken> certs = new HashSet<>();
		for (TrustServiceProvider tslServiceProvider : trustServiceProviders) {
			List<TrustService> services = tslServiceProvider.getServices();
			for (TrustService tslService : services) {
				certs.addAll(tslService.getCertificates());
			}
		}
		assertEquals(413, certs.size());
	}

	@Test
	void dss1911() throws ParseException {
		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");

		TLParsingTask task = new TLParsingTask(SK_1911, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertEquals(1, trustServiceProviders.size());
		TrustServiceProvider uniqueTSP = trustServiceProviders.get(0);
		List<TrustService> services = uniqueTSP.getServices();
		assertEquals(1, services.size());
		TrustService uniqueService = services.get(0);
		assertNotNull(uniqueService);
		
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> statusAndInformationExtensions = uniqueService.getStatusAndInformationExtensions();
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		Date date = sdf.parse("2019-08-01");

		TrustServiceStatusAndInformationExtensions forDate = statusAndInformationExtensions.getCurrent(date);
		assertNotNull(forDate);
		List<ConditionForQualifiers> conditionsForQualifiers = forDate.getConditionsForQualifiers();
		assertEquals(2, conditionsForQualifiers.size());

		for (ConditionForQualifiers conditionForQualifiers : conditionsForQualifiers) {
			assertTrue(conditionForQualifiers.getCondition().check(certificate));
		}
	}

	@Test
	void qualifierExtractionTest() {
		// see DSS-2772

		TLParsingTask task = new TLParsingTask(FR_TL, new TLSource());
		TLParsingResult result = task.get();
		assertNotNull(result);

		List<TrustServiceProvider> trustServiceProviders = result.getTrustServiceProviders();
		assertEquals(24, trustServiceProviders.size());

		TrustServiceProvider docusign = null;
		for (TrustServiceProvider tsp : trustServiceProviders) {
			if ("Docusign France".equals(tsp.getNames().get("en").get(0))) {
				docusign = tsp;
				break;
			}
		}
		assertNotNull(docusign);

		List<TrustService> services = docusign.getServices();
		assertEquals(9, services.size());

		List<String> qualifiersMax = new ArrayList<>();
		for (TrustService ts : services) {
			List<String> qualifiers = new ArrayList<>();
			TrustServiceStatusAndInformationExtensions latest = ts.getStatusAndInformationExtensions().getLatest();
			List<ConditionForQualifiers> conditionsForQualifiers = latest.getConditionsForQualifiers();
			for (ConditionForQualifiers conditionForQualifiers : conditionsForQualifiers) {
				qualifiers.addAll(conditionForQualifiers.getQualifiers());
			}
			if (qualifiers.size() > qualifiersMax.size()) {
				qualifiersMax = qualifiers;
			}
		}
		assertEquals(4, qualifiersMax.size());

		assertTrue(qualifiersMax.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"));
		assertTrue(qualifiersMax.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"));
		assertTrue(qualifiersMax.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD"));
		assertTrue(qualifiersMax.contains("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal"));
	}

}
