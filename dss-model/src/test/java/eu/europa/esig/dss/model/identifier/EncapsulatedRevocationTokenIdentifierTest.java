package eu.europa.esig.dss.model.identifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

public class EncapsulatedRevocationTokenIdentifierTest {

	@Test
	public void test() {
		EncapsulatedRevocationTokenIdentifier id1 = new EncapsulatedRevocationTokenIdentifier(new byte[] { 1, 2, 3 });
		EncapsulatedRevocationTokenIdentifier id2 = new EncapsulatedRevocationTokenIdentifier(new byte[] { 1, 2, 3 });
		EncapsulatedRevocationTokenIdentifier id3 = new EncapsulatedRevocationTokenIdentifier(new byte[] { 1, 2, 2 });

		assertEquals(id1, id2);
		assertEquals(id1.hashCode(), id2.hashCode());
		assertNotEquals(id1, id3);
		assertNotEquals(id1.hashCode(), id3.hashCode());

		Map<EncapsulatedRevocationTokenIdentifier, String> map = new HashMap<>();
		map.put(id1, "bla");
		map.put(id2, "bla");
		map.put(id3, "bla");
		assertEquals(2, map.keySet().size());
	}

	@Test
	public void assertNPE() {
		assertThrows(NullPointerException.class, () -> new EncapsulatedRevocationTokenIdentifier(null));
	}

}
