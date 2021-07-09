/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.identifier;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class IdentifierTest {

	@Test
	public void testEquals() {

		byte[] bytes = new byte[] { 1, 2, 3, 4, 5, 6 };

		byte[] bytes2 = new byte[] { 1, 2, 3, 5, 5, 6 };

		MockIdentifier t1 = new MockIdentifier(bytes);
		MockIdentifier t2 = new MockIdentifier(bytes);
		MockIdentifier t3 = new MockIdentifier(bytes2);

		assertEquals(t1, t2);
		assertNotEquals(t1, t3);

		String id1 = t1.asXmlId();
		String id2 = t2.asXmlId();
		String id3 = t3.asXmlId();

		assertEquals(id1, id2);
		assertNotEquals(id2, id3);
	}

	private static class MockIdentifier extends Identifier {

		private static final long serialVersionUID = 473449731636785224L;

		MockIdentifier(byte[] data) {
			super("M-", data);
		}

	}

}
