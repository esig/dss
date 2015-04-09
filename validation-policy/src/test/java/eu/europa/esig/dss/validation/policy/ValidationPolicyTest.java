package eu.europa.esig.dss.validation.policy;

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

public class ValidationPolicyTest {

	@Test
	public void test1() throws Exception {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		byte[] data = IOUtils.toByteArray(getClass().getResourceAsStream("/policy/constraint.xml"));

		EtsiValidationPolicy policy = new EtsiValidationPolicy(dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data)));

		assertNotNull(policy);
	}

}
