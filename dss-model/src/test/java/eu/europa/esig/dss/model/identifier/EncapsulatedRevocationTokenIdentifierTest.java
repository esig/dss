/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.identifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

class EncapsulatedRevocationTokenIdentifierTest {

	@Test
	@SuppressWarnings("rawtypes")
	void test() {
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
	@SuppressWarnings("rawtypes")
	void assertNPE() {
		assertThrows(NullPointerException.class, () -> new EncapsulatedRevocationTokenIdentifier(null));
	}

}
