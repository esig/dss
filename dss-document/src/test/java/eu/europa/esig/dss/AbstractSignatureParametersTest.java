package eu.europa.esig.dss;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;

/**
 * Unit test to fix https://esig-dss.atlassian.net/browse/DSS-672
 */
public class AbstractSignatureParametersTest {

	private static final Logger logger = LoggerFactory.getLogger(AbstractSignatureParametersTest.class);

	@Test
	public void testToString() {
		CommonSignatureParamaters commonSignatureParamaters = new CommonSignatureParamaters();
		logger.info(commonSignatureParamaters.toString());
	}

	private static class CommonSignatureParamaters extends AbstractSignatureParameters {}
}
