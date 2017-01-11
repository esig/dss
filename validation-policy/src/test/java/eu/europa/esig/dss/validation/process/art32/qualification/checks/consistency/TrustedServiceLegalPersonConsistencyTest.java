package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.art32.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceLegalPersonConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceLegalPersonConsistency();

	@Test
	public void testEmpty() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testLegalOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_LEGAL_PERSON);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testESigOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_LEGAL_PERSON);
		service.getCapturedQualifiers().add(ServiceQualification.QC_FOR_ESIG);
		assertFalse(condition.isConsistent(service));
	}

}
