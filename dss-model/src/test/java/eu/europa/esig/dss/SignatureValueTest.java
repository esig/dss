package eu.europa.esig.dss;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureValueTest {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureValueTest.class);

	@Test
	public void testToString() {
		SignatureValue sv = new SignatureValue();
		LOG.info("{}", sv);
		sv.setAlgorithm(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1);
		sv.setValue(new byte[] { 1, 2, 3 });
		LOG.info("{}", sv);
	}

}
