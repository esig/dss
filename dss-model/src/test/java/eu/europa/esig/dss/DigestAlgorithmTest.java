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
package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DigestAlgorithmTest {

	@Test
	public void forOid() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forOID(DigestAlgorithm.SHA256.getOid()));
	}

	@Test(expected = DSSException.class)
	public void forOidException() {
		DigestAlgorithm.forOID("aaa");
	}

	@Test
	public void forXML() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forXML(DigestAlgorithm.SHA256.getXmlId()));
	}

	@Test(expected = DSSException.class)
	public void forXMLException() {
		DigestAlgorithm.forXML("aaa");
	}

	@Test
	public void forXMLSubstitution() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forXML("aaa", DigestAlgorithm.SHA256));
	}

	@Test
	public void forName() {
		for (DigestAlgorithm digestAlgo : DigestAlgorithm.values()) {
			assertEquals(digestAlgo, DigestAlgorithm.forName(digestAlgo.getName()));
		}
	}

	@Test(expected = DSSException.class)
	public void forNameException() {
		DigestAlgorithm.forName("aaa");
	}

	@Test
	public void forNameSubstitution() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forName("aaa", DigestAlgorithm.SHA256));
	}

}
