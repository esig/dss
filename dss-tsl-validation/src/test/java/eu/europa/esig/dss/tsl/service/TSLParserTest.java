package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.TSLConditionsForQualifiers;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.jaxb.ecc.CriteriaListType;
import eu.europa.esig.jaxb.ecc.KeyUsageBitType;
import eu.europa.esig.jaxb.ecc.KeyUsageType;
import eu.europa.esig.jaxb.ecc.PoliciesListType;
import eu.europa.esig.jaxb.xades.IdentifierType;
import eu.europa.esig.jaxb.xades.ObjectIdentifierType;

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
		assertTrue(Utils.isCollectionNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(Utils.isStringNotEmpty(tslPointer.getMimeType()));
			assertTrue(Utils.isStringNotEmpty(tslPointer.getTerritory()));
			assertTrue(Utils.isStringNotEmpty(tslPointer.getUrl()));
			assertTrue(Utils.isCollectionNotEmpty(tslPointer.getPotentialSigners()));
		}
		assertTrue(Utils.isCollectionNotEmpty(model.getDistributionPoints()));
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
				certs.addAll(tslService.getCertificates());
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
				certs.addAll(tslService.getCertificates());
			}
		}
		assertEquals(oldResult, certs.size());
	}

	@Test
	public void serviceQualificationEE() throws Exception {
		// ***************************** OLD VERSION OF TL
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/0A191C3E18CAB7B783E690D3E4431C354A068FF0.xml")));
		TSLParserResult model = parser.call();

		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		assertEquals(2, serviceProviders.size());

		TSLService service = getESTEIDSK2007(serviceProviders);
		assertNotNull(service);

		TSLServiceStatusAndInformationExtensions latestStatusAndExtensions = service.getStatusAndInformationExtensions().getLatest();
		List<TSLConditionsForQualifiers> conditionsForQualifiers = latestStatusAndExtensions.getConditionsForQualifiers();
		assertEquals(1, conditionsForQualifiers.size());

		TSLConditionsForQualifiers qcStatement = getQualificationQCStatement(conditionsForQualifiers);
		assertNull(qcStatement);

		// ***************************** NEW VERSION OF TL

		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFRTEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEPMA0GA1UECxMGRVNURUlEMRcwFQYDVQQDEw5FU1RFSUQtU0sgMjAwNzAeFw0wODA0MDYwOTUzMDlaFw0xMjAzMDUyMjAwMDBaMIGWMQswCQYDVQQGEwJFRTEPMA0GA1UEChMGRVNURUlEMRowGAYDVQQLExFkaWdpdGFsIHNpZ25hdHVyZTEiMCAGA1UEAxMZU0lOSVZFRSxWRUlLTywzNjcwNjAyMDIxMDEQMA4GA1UEBBMHU0lOSVZFRTEOMAwGA1UEKhMFVkVJS08xFDASBgNVBAUTCzM2NzA2MDIwMjEwMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGRN42R9e6VEHMCyvacuubjtm1+5Kk92WgIgtWA8hY8DW2iNvQJ3jOF5XlVIyIDTwl2JVKxWKhXX+8+yNFPpqAK43IINcmMfznw/KcR7jACGNuTrivA9HrvRiqDzTg5E1rktjho6OkDkdV3dgOLB2wyhVm2anNpICfrUq8c09HPwIDMMP5o4HvMIHsMA4GA1UdDwEB/wQEAwIGQDA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL2VzdGVpZDIwMDcuY3JsMFEGA1UdIARKMEgwRgYLKwYBBAHOHwEBAQEwNzASBggrBgEFBQcCAjAGGgRub25lMCEGCCsGAQUFBwIBFhVodHRwOi8vd3d3LnNrLmVlL2Nwcy8wHwYDVR0jBBgwFoAUSAbevoyHV5WAeGP6nCMrK6A6GHUwHQYDVR0OBBYEFJAJUyDrH3rdxTStU+LDa6aHdE8dMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEFBQADggEBAA5qjfeuTdOoEtatiA9hpjDHzyqN1PROcaPrABXGqpLxcHbLVr7xmovILAjxS9fJAw28u9ZE3asRNa9xgQNTeX23mMlojJAYVbYCeIeJ6jtsRiCo34wgvO3CtVfO3+C1T8Du5XLCHa6SoT8SpCApW+Crwe+6eCZDmv2NKTjhn1wCCNO2e8HuSt+pTUNBTUB+rkvF4KO9VnuzRzT7zN7AUdW4OFF3bI+9+VmW3t9vq1zDOxNTdBkCM3zm5TRa8ZtyAPL48bW19JAcYzQLjPGORwoIRNSXdVTqX+cDiw2wbmb2IhPdxRqN9uPwU1x/ltZZ3W5GzJ1t8JeQN7PuGM0OHqE=");

		parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/0A191C3E18CAB7B783E690D3E4431C354A068FF0-2.xml")));
		model = parser.call();

		serviceProviders = model.getServiceProviders();
		assertEquals(2, serviceProviders.size());

		service = getESTEIDSK2007(serviceProviders);
		assertNotNull(service);

		latestStatusAndExtensions = service.getStatusAndInformationExtensions().getLatest();
		conditionsForQualifiers = latestStatusAndExtensions.getConditionsForQualifiers();
		assertEquals(2, conditionsForQualifiers.size());

		qcStatement = getQualificationQCStatement(conditionsForQualifiers);
		assertNotNull(qcStatement);

		Condition condition = qcStatement.getCondition();
		assertTrue(condition.check(certificate));
	}

	@Test
	public void getAdditionnalServiceInfo() throws Exception {
		TSLParser parser = new TSLParser(new FileInputStream(new File("src/test/resources/tsls/tsl-be-v5.xml")));
		TSLParserResult model = parser.call();

		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();
		assertEquals(4, serviceProviders.size());

		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			if ("Certipost n.v./s.a.".equals(tslServiceProvider.getName())) {
				List<TSLService> services = tslServiceProvider.getServices();
				assertEquals(6, services.size());
			}
		}

	}

	private TSLConditionsForQualifiers getQualificationQCStatement(List<TSLConditionsForQualifiers> conditionsForQualifiers) {
		for (TSLConditionsForQualifiers tslConditionsForQualifiers : conditionsForQualifiers) {
			List<String> qualifiers = tslConditionsForQualifiers.getQualifiers();
			for (String qualifier : qualifiers) {
				if ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement".equals(qualifier)) {
					return tslConditionsForQualifiers;
				}
			}
		}
		return null;
	}

	private TSLService getESTEIDSK2007(List<TSLServiceProvider> serviceProviders) {
		String serviceNameToFind = "ESTEID-SK 2007: Qualified certificates for Estonian ID-card, the residence permit card, the digital identity card, the digital identity card in form of the Mobile-ID";
		TSLService service = null;

		for (TSLServiceProvider tslServiceProvider : serviceProviders) {
			List<TSLService> services = tslServiceProvider.getServices();
			for (TSLService tslService : services) {
				if (serviceNameToFind.equals(tslService.getName())) {
					service = tslService;
					break;
				}
			}
		}
		return service;
	}

	@Test
	public void testMultiPolicySet() {
		PoliciesListType policiesA = new PoliciesListType();
		policiesA.getPolicyIdentifier().add(oid("2.999.4"));
		policiesA.getPolicyIdentifier().add(oid("2.999.5"));

		PoliciesListType policiesB = new PoliciesListType();
		policiesB.getPolicyIdentifier().add(oid("2.999.6"));
		policiesB.getPolicyIdentifier().add(oid("2.999.7"));

		CriteriaListType criteria = new CriteriaListType();
		criteria.setAssert("atLeastOne");
		criteria.getPolicySet().add(policiesA);
		criteria.getPolicySet().add(policiesB);

		KeyUsageType keyUsageA = new KeyUsageType();
		keyUsageA.getKeyUsageBit().add(kub("dataEncipherment", false));
		keyUsageA.getKeyUsageBit().add(kub("decipherOnly", true));
		criteria.getKeyUsage().add(keyUsageA);

		KeyUsageType keyUsageB = new KeyUsageType();
		keyUsageB.getKeyUsageBit().add(kub("encipherOnly", false));
		keyUsageB.getKeyUsageBit().add(kub("keyCertSign", true));
		criteria.getKeyUsage().add(keyUsageB);

		criteria.getCriteriaList().add(getSubCriteria());

		Condition condition = new TSLParser(null).getCondition(criteria);
		System.out.println(condition.toString(""));
	}

	private CriteriaListType getSubCriteria() {
		PoliciesListType policiesA = new PoliciesListType();
		policiesA.getPolicyIdentifier().add(oid("1.2.3"));
		policiesA.getPolicyIdentifier().add(oid("4.5.6"));

		PoliciesListType policiesB = new PoliciesListType();
		policiesB.getPolicyIdentifier().add(oid("7.8.9"));
		policiesB.getPolicyIdentifier().add(oid("22.33.44"));

		CriteriaListType criteria = new CriteriaListType();
		criteria.setAssert("all");
		criteria.getPolicySet().add(policiesA);
		criteria.getPolicySet().add(policiesB);
		return criteria;
	}

	private KeyUsageBitType kub(String kub, boolean val) {
		KeyUsageBitType keyUsageBitType = new KeyUsageBitType();
		keyUsageBitType.setName(kub);
		keyUsageBitType.setValue(val);
		return keyUsageBitType;
	}

	private static ObjectIdentifierType oid(String value) {
		IdentifierType identifier = new IdentifierType();
		identifier.setValue(value);
		ObjectIdentifierType objectIdentifier = new ObjectIdentifierType();
		objectIdentifier.setIdentifier(identifier);
		return objectIdentifier;
	}
}
