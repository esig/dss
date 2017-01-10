package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.TrustedServiceCondition;

public class TrustedServiceQSCDConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceQSCDConsistency();

	@Test
	public void testNoInfo() {
		XmlTrustedService service = new XmlTrustedService();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testSSCD() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_WITH_QSCD);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testNoSSCD() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_NO_QSCD);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_WITH_QSCD);
		service.getCapturedQualifiers().add(ServiceQualification.QC_NO_QSCD);
		assertFalse(condition.isConsistent(service));
	}

}
