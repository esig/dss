package eu.europa.esig.dss;

import org.junit.Test;

import eu.europa.esig.dss.validation.ValidationResourceManager;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class LoadInvalidPolicyTest {

	@Test(expected = DSSException.class)
	public void test() {
		ConstraintsParameters result = ValidationResourceManager.load("src/test/resources/invalid-policy.xml");
	}
}
