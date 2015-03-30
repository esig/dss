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
package eu.europa.ec.markt.dss;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.Test;

public class ASN1ObjectIdentifierComparatorTest {

	@Test
	public void test1() {
		List<ASN1ObjectIdentifier> oids = new ArrayList<ASN1ObjectIdentifier>();
		oids.add(PKCSObjectIdentifiers.id_aa_receiptRequest); //1.2.840.113549.1.9.16.2.1
		oids.add(PKCSObjectIdentifiers.id_aa); // 1.2.840.113549.1.9.16.2

		Collections.sort(oids, new ASN1ObjectIdentifierComparator());

		assertEquals(PKCSObjectIdentifiers.id_aa, oids.get(0));
		assertEquals(PKCSObjectIdentifiers.id_aa_receiptRequest, oids.get(1));
	}

	@Test
	public void test2() {
		List<ASN1ObjectIdentifier> oids = new ArrayList<ASN1ObjectIdentifier>();
		oids.add(PKCSObjectIdentifiers.id_aa); // 1.2.840.113549.1.9.16.6.2
		oids.add(PKCSObjectIdentifiers.id_aa_receiptRequest); //1.2.840.113549.1.9.16.2.1

		Collections.sort(oids, new ASN1ObjectIdentifierComparator());

		assertEquals(PKCSObjectIdentifiers.id_aa, oids.get(0));
		assertEquals(PKCSObjectIdentifiers.id_aa_receiptRequest, oids.get(1));
	}

	@Test
	public void test3() {
		List<ASN1ObjectIdentifier> oids = new ArrayList<ASN1ObjectIdentifier>();
		oids.add(PKCSObjectIdentifiers.id_aa); 					// 1.2.840.113549.1.9.16.2
		oids.add(PKCSObjectIdentifiers.id_alg); 				// 1.2.840.113549.1.9.16.3
		oids.add(PKCSObjectIdentifiers.id_aa_receiptRequest); 	// 1.2.840.113549.1.9.16.2.1
		oids.add(PKCSObjectIdentifiers.pkcs_9);					// 1.2.840.113549.1.9

		Collections.sort(oids, new ASN1ObjectIdentifierComparator());

		assertEquals(PKCSObjectIdentifiers.pkcs_9, oids.get(0));
		assertEquals(PKCSObjectIdentifiers.id_aa, oids.get(1));
		assertEquals(PKCSObjectIdentifiers.id_aa_receiptRequest, oids.get(2));
		assertEquals(PKCSObjectIdentifiers.id_alg, oids.get(3));
	}

}
