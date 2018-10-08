package eu.europa.esig.dss.validation.policy;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;

public class DateUtilsTest {

	@Test
	public void test( ) {
		assertNotNull(DateUtils.parseDate(DateUtils.DEFAULT_DATE_FORMAT, "2020-02-22"));
	}

	@Test(expected = DSSException.class)
	public void testException() {
		DateUtils.parseDate(DateUtils.DEFAULT_DATE_FORMAT, "20-2020-02");
	}

}
