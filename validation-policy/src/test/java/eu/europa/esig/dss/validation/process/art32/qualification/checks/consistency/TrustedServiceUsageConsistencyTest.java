package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceUsageConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceUsageConsistency();

	@Test
	public void testNoUsage() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testForEsigUsage() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testForEsigAndEsealsUsage() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESEAL);
		assertFalse(condition.isConsistent(service));
	}

}
