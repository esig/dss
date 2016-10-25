package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenIdentifierTest {

	private static final Logger logger = LoggerFactory.getLogger(TokenIdentifierTest.class);

	@Test
	public void testEquals() {

		byte[] bytes = new byte[] {
				1, 2, 3, 4, 5, 6
		};

		byte[] bytes2 = new byte[] {
				1, 2, 3, 5, 5, 6
		};

		TokenIdentifier t1 = new TokenIdentifier(bytes);
		TokenIdentifier t2 = new TokenIdentifier(bytes);
		TokenIdentifier t3 = new TokenIdentifier(bytes2);

		assertEquals(t1, t2);
		Assert.assertNotEquals(t1,t3);

		String id1 = t1.asXmlId();
		logger.info("T1 = " + t1 + " : " + id1);
		String id2 = t2.asXmlId();
		logger.info("T2 = " + t2 + " : " + id2);
		String id3 = t3.asXmlId();
		logger.info("T3 = " + t3 + " : " + id3);

		assertEquals(id1, id2);
		Assert.assertNotEquals(id2,id3);
	}

}
