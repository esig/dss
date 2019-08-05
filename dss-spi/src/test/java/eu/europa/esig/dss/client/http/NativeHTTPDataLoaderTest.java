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
package eu.europa.esig.dss.client.http;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class NativeHTTPDataLoaderTest {

	private static final String HTTP_URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";
	private static final String FILE_URL_TO_LOAD = "file:src/test/resources/belgiumrs2.crt";

	@Test
	public void testHttpGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(HTTP_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	public void testFileGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(FILE_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test(expected=DSSException.class)
	public void testGetBiggerThanMaxSize() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setMaxInputSize(1);
		
		dataLoader.get(FILE_URL_TO_LOAD);
	}

	@Test(expected=DSSException.class)
	public void testGetTimeout() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setTimeout(1);
		
		dataLoader.get(HTTP_URL_TO_LOAD);
	}
}
