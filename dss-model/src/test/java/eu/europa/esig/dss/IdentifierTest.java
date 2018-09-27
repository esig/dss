package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

public class IdentifierTest {

	@Test
	public void testEquals() {

		byte[] bytes = new byte[] { 1, 2, 3, 4, 5, 6 };

		byte[] bytes2 = new byte[] { 1, 2, 3, 5, 5, 6 };

		MockIdentifier t1 = new MockIdentifier(bytes);
		MockIdentifier t2 = new MockIdentifier(bytes);
		MockIdentifier t3 = new MockIdentifier(bytes2);

		assertEquals(t1, t2);
		Assert.assertNotEquals(t1, t3);

		String id1 = t1.asXmlId();
		String id2 = t2.asXmlId();
		String id3 = t3.asXmlId();

		assertEquals(id1, id2);
		Assert.assertNotEquals(id2, id3);
	}

	private class MockIdentifier extends Identifier {

		private static final long serialVersionUID = 473449731636785224L;

		MockIdentifier(byte[] data) {
			super(data);
		}

	}

}
