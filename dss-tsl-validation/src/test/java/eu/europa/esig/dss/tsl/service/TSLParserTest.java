package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;

import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.x509.CertificateToken;

public class TSLParserTest {

	@Test
	public void parseLOTL() throws Exception {
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/LOTL.xml")));
		TSLParserResult model = parser.call();
		assertNotNull(model);
		assertNotNull(model.getNextUpdateDate());
		assertNotNull(model.getIssueDate());
		assertEquals("EU", model.getTerritory());
		assertEquals(115, model.getSequenceNumber());
		List<TSLPointer> pointers = model.getPointers();
		assertTrue(CollectionUtils.isNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(StringUtils.isNotEmpty(tslPointer.getMimeType()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getTerritory()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getUrl()));
			assertTrue(CollectionUtils.isNotEmpty(tslPointer.getPotentialSigners()));
		}
		assertTrue(CollectionUtils.isNotEmpty(model.getDistributionPoints()));
	}

	@Test
	public void countCertificatesLT() throws Exception {
		int oldResult = 35;
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/621C7723265CA33AAD0607B3C612B313872E7514.xml")));
		TSLParserResult model = parser.call();

		Set<CertificateToken> certs = new HashSet<CertificateToken>();
		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				certs.addAll( tslService.getCertificates());
			}
		}
		assertEquals(oldResult, certs.size());
	}

	@Test
	public void countCertificatesDE() throws Exception {
		int oldResult = 413;
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/59F95095730A1809A027655246D6524959B191A8.xml")));
		TSLParserResult model = parser.call();

		Set<CertificateToken> certs = new HashSet<CertificateToken>();
		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				certs.addAll( tslService.getCertificates());
			}
		}
		assertEquals(oldResult, certs.size());
	}

}
