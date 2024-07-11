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
package eu.europa.esig.dss.spi.client.http;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MaxSizeInputStreamTest {

    private static final String HTTP_URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";

    private URLConnection urlConnection;

    @BeforeEach
    void init() throws Exception {
        urlConnection = new URL(HTTP_URL_TO_LOAD).openConnection();;
        urlConnection.setDoInput(true);
    }

    @Test
    void readByByteTest() throws IOException {
        byte[] result;
        try (InputStream is = urlConnection.getInputStream();
             MaxSizeInputStream maxSizeInputStream = new MaxSizeInputStream(is, 1000000, HTTP_URL_TO_LOAD);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int b;
            while ((b = maxSizeInputStream.read()) != -1) {
                baos.write((byte) b);
            }
            result = baos.toByteArray();
        }
        assertTrue(Utils.isArrayNotEmpty(result));
        CertificateToken certificate = DSSUtils.loadCertificate(result);
        assertNotNull(certificate);
    }

    @Test
    void readByByteWithLimitTest() {
        boolean exceptionThrown = false;
        try (InputStream is = urlConnection.getInputStream();
             MaxSizeInputStream maxSizeInputStream = new MaxSizeInputStream(is, 10, HTTP_URL_TO_LOAD);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            int b;
            while ((b = maxSizeInputStream.read()) != -1) {
                baos.write((byte) b);
            }
        } catch (IOException e) {
            exceptionThrown = true;
            assertEquals("Cannot fetch data limit=10, url=http://certs.eid.belgium.be/belgiumrs2.crt", e.getMessage());
        }
        assertTrue(exceptionThrown);
    }

    @Test
    void readWithBufferArrayTest() throws IOException {
        byte[] result;
        try (InputStream is = urlConnection.getInputStream();
             MaxSizeInputStream maxSizeInputStream = new MaxSizeInputStream(is, 1000000, HTTP_URL_TO_LOAD);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final byte[] buffer = new byte[2048];
            int count;
            while ((count = maxSizeInputStream.read(buffer, 0, buffer.length)) > 0) {
                baos.write(buffer);
            }
            result = baos.toByteArray();
        }
        assertTrue(Utils.isArrayNotEmpty(result));
        CertificateToken certificate = DSSUtils.loadCertificate(result);
        assertNotNull(certificate);
    }

    @Test
    void readWithBufferArrayWithLimitTest() {
        boolean exceptionThrown = false;
        try (InputStream is = urlConnection.getInputStream();
             MaxSizeInputStream maxSizeInputStream = new MaxSizeInputStream(is, 10, HTTP_URL_TO_LOAD);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final byte[] buffer = new byte[2048];
            int count;
            while ((count = maxSizeInputStream.read(buffer, 0, buffer.length)) > 0) {
                baos.write(buffer);
            }
        } catch (IOException e) {
            exceptionThrown = true;
            assertEquals("Cannot fetch data limit=10, url=http://certs.eid.belgium.be/belgiumrs2.crt", e.getMessage());
        }
        assertTrue(exceptionThrown);
    }

}
