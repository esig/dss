package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.TrustedServiceCondition;

public class TrustedServiceLegalPersonConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceLegalPersonConsistency();

	@Test
	public void testEmpty() {
		XmlTrustedService service = new XmlTrustedService();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testLegalOnly() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_LEGAL_PERSON);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testESigOnly() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_LEGAL_PERSON);
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		assertFalse(condition.isConsistent(service));
	}

}
