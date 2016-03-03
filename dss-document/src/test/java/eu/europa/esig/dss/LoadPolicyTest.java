package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;

import org.junit.Test;

import eu.europa.esig.dss.validation.ValidationResourceManager;

public class LoadPolicyTest {

	@Test(expected = DSSException.class)
	public void testInvalid() {
		ValidationResourceManager.load("src/test/resources/invalid-policy.xml");
	}

	@Test
	public void testValid() throws Exception {
		assertNotNull(ValidationResourceManager.loadPolicyData(new FileInputStream("src/test/resources/constraint.xml")));
	}

}
