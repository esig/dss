package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;

public class TrustedServiceUsageConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceUsageConsistency();

	@Test
	public void testNoUsage() {
		XmlTrustedService service = new XmlTrustedService();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testForEsigUsage() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testForEsigAndEsealsUsage() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESEAL);
		assertFalse(condition.isConsistent(service));
	}

}
