package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceQCStatementConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceQCStatementConsistency();

	@Test
	public void testEmpty() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testQCStatementOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_STATEMENT);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testNoQualifiedOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.NOT_QUALIFIED);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_STATEMENT);
		service.getCapturedQualifiers().add(ServiceQualification.NOT_QUALIFIED);
		assertFalse(condition.isConsistent(service));
	}

}
