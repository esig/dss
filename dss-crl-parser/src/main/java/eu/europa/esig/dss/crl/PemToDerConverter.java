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
package eu.europa.esig.dss.crl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import eu.europa.esig.dss.model.DSSException;

/**
 * This class is used to convert PEM encoded binaries (CRL, Cert) to DER encoded representation
 *
 */
public final class PemToDerConverter {

	private PemToDerConverter() {
		// empty
	}

	/**
	 * Converts PEM encoded binaries to DER encoded equivalent
	 * 
	 * @param pemEncoded the PEM encoded byte array
	 * @return DER encoded byte array
	 */
	public static byte[] convert(final byte[] pemEncoded) {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(pemEncoded);
				Reader reader = new InputStreamReader(bais);
				PemReader pemReader = new PemReader(reader)) {
			PemObject pemObject = pemReader.readPemObject();
			if (pemObject == null) {
				throw new DSSException("Unable to read PEM Object");
			}
			byte[] binaries = pemObject.getContent();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			os.write(binaries, 0, binaries.length);
			return os.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Unable to convert the CRL to DER", e);
		}
	}

}
