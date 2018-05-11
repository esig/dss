package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceCondition;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceQSCDConsistency;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceQSCDConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceQSCDConsistency();

	@Test
	public void testNoInfo() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_WITH_QSCD));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testNoQSCD() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_NO_QSCD));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_NO_QSCD, ServiceQualification.QC_WITH_QSCD));
		assertFalse(condition.isConsistent(service));
	}

}
