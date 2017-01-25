package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.ServiceQualification;
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
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_STATEMENT));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testNoQualifiedOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.NOT_QUALIFIED));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.NOT_QUALIFIED, ServiceQualification.QC_STATEMENT));
		assertFalse(condition.isConsistent(service));
	}

}
