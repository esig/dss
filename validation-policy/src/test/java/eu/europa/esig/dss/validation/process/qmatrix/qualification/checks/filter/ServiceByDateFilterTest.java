package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class ServiceByDateFilterTest {

	private final static Date DATE1 = DatatypeConverter.parseDateTime("2015-07-01T00:00:00-00:00").getTime();
	private final static Date DATE2 = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();
	private final static Date DATE3 = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

	@Test
	public void noCAQC() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);
		assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<TrustedServiceWrapper>())));
	}

	@Test
	public void testInRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);

		assertTrue(filter.isAcceptable(service));
	}

	@Test
	public void testNoEndRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);

		assertTrue(filter.isAcceptable(service));
	}

	@Test
	public void testNoDateRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		TrustedServiceWrapper service = new TrustedServiceWrapper();

		assertFalse(filter.isAcceptable(service));
	}

	@Test
	public void testNotInRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE3);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE2);

		assertFalse(filter.isAcceptable(service));
	}

	@Test
	public void testInRangeSameStartDate() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE1);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);

		assertTrue(filter.isAcceptable(service));
	}

	@Test
	public void testInRangeSameEndDate() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE3);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);

		assertTrue(filter.isAcceptable(service));
	}

}
