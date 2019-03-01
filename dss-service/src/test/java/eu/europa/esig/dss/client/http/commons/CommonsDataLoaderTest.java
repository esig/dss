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
package eu.europa.esig.dss.client.http.commons;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public class CommonsDataLoaderTest {

	private static final String URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";

	private CommonsDataLoader dataLoader = new CommonsDataLoader();

	@Test
	public void testGet() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);

		NativeHTTPDataLoader dataLoader2 = new NativeHTTPDataLoader();
		byte[] bytesArrays2 = dataLoader2.get(URL_TO_LOAD);

		assertTrue(Arrays.equals(bytesArray, bytesArrays2));

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	public void ldapTest1() {
		String url = "ldap://x500.gov.si/ou=sigen-ca,o=state-institutions,c=si?certificateRevocationList?base";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}

	@Test
	public void ldapTest2() {
		String url = "ldap://postarca.posta.si/ou=POSTArCA,o=POSTA,c=SI?certificateRevocationList";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}

	@Test
	public void ldapTest3() {
		String url = "ldap://acldap.nlb.si/o=ACNLB,c=SI?certificateRevocationList";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}
	
	@Test
	public void dss1583test() {
		String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Systems%20International%20GmbH,c=de";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH,c=de";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH%20,%20c=de%20";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International%20GmbH , c=de";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de?certificateRevocationList?base";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}
	
	@Test
	public void dss1583WarningTest() {
		String url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de%2";
		assertFalse(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Syste%ms International GmbH,c=de";
		assertFalse(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-SystemsInternational GmbH,c=de";
		assertFalse(Utils.isArrayNotEmpty(dataLoader.get(url)));
		url = "ldap://pks-ldap.telesec.de/o=T-Systems International GmbH,c=de?certificate";
		assertFalse(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}

}
