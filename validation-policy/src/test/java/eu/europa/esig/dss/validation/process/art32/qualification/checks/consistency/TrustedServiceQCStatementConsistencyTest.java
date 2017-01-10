package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.TrustedServiceCondition;

public class TrustedServiceQCStatementConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceQCStatementConsistency();

	@Test
	public void testEmpty() {
		XmlTrustedService service = new XmlTrustedService();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testQCStatementOnly() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_STATEMENT);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testNoQualifiedOnly() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.NOT_QUALIFIED);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		XmlTrustedService service = new XmlTrustedService();
		service.getCapturedQualifiers().add(ServiceQualification.QC_STATEMENT);
		service.getCapturedQualifiers().add(ServiceQualification.NOT_QUALIFIED);
		assertFalse(condition.isConsistent(service));
	}

}
