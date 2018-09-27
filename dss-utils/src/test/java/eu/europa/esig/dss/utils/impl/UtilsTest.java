package eu.europa.esig.dss.utils.impl;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;

public class UtilsTest {

	@Test(expected = ExceptionInInitializerError.class)
	public void testNoImplementationException() {
		Utils.isStringBlank("test");
	}

}
