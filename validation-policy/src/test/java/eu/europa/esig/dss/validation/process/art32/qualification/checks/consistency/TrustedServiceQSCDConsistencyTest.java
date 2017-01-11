package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceQSCDConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceQSCDConsistency();

	@Test
	public void testNoInfo() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testSSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_WITH_QSCD);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testNoSSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_NO_QSCD);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_WITH_QSCD);
		service.getCapturedQualifiers().add(ServiceQualification.QC_NO_QSCD);
		assertFalse(condition.isConsistent(service));
	}

}
