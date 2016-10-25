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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;

import org.junit.Assert;
import org.junit.Test;

public class DigestTest {

	@Test
	public void testEquals() throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] value = md.digest("Hello World !".getBytes());

		Digest d1 = new Digest(DigestAlgorithm.SHA256, value);
		Digest d2 = new Digest(DigestAlgorithm.SHA256, value);

		Assert.assertEquals(d1,d2);
		Assert.assertEquals(d1.hashCode(), d2.hashCode());

	}

	@Test
	public void testSerializable() throws Exception {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] value = md.digest("Hello World !".getBytes());

		Digest d1 = new Digest(DigestAlgorithm.SHA256, value);

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(buffer);
		out.writeObject(d1);
		out.close();

		ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()));
		Digest d2 = (Digest) in.readObject();

		Assert.assertEquals(d1,d2);
		Assert.assertEquals(d1.hashCode(),d2.hashCode());

	}

}
