package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;

public class ServiceByDateFilterTest {

	private final static Date DATE1 = DatatypeConverter.parseDateTime("2015-07-01T00:00:00-00:00").getTime();
	private final static Date DATE2 = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();
	private final static Date DATE3 = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

	@Test
	public void testInRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		List<XmlTrustedService> trustedServices = new ArrayList<XmlTrustedService>();

		XmlTrustedService service = new XmlTrustedService();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);
		trustedServices.add(service);

		List<XmlTrustedService> acceptableServices = filter.getAcceptableServices(trustedServices);
		assertEquals(1, acceptableServices.size());
	}

	@Test
	public void testNoEndRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		List<XmlTrustedService> trustedServices = new ArrayList<XmlTrustedService>();

		XmlTrustedService service = new XmlTrustedService();
		service.setStartDate(DATE1);
		trustedServices.add(service);

		List<XmlTrustedService> acceptableServices = filter.getAcceptableServices(trustedServices);
		assertEquals(1, acceptableServices.size());
	}

	@Test
	public void testNotInRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE3);

		List<XmlTrustedService> trustedServices = new ArrayList<XmlTrustedService>();

		XmlTrustedService service = new XmlTrustedService();
		service.setStartDate(DATE1);
		service.setEndDate(DATE2);
		trustedServices.add(service);

		List<XmlTrustedService> acceptableServices = filter.getAcceptableServices(trustedServices);
		assertEquals(0, acceptableServices.size());
	}

	@Test
	public void testInRangeSameStartDate() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE1);

		List<XmlTrustedService> trustedServices = new ArrayList<XmlTrustedService>();

		XmlTrustedService service = new XmlTrustedService();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);
		trustedServices.add(service);

		List<XmlTrustedService> acceptableServices = filter.getAcceptableServices(trustedServices);
		assertEquals(1, acceptableServices.size());
	}

	@Test
	public void testInRangeSameEndDate() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE3);

		List<XmlTrustedService> trustedServices = new ArrayList<XmlTrustedService>();

		XmlTrustedService service = new XmlTrustedService();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);
		trustedServices.add(service);

		List<XmlTrustedService> acceptableServices = filter.getAcceptableServices(trustedServices);
		assertEquals(1, acceptableServices.size());
	}

}
