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
package eu.europa.esig.dss.crl.stream.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;

import org.bouncycastle.asn1.ASN1InputStream;

/**
 * This class is used to access to static methods of ASN1InputStream
 */
final class DERUtil {

	private static Method READ_LENGTH;
	private static Method READ_TAG_NUMBER;

	static {
		try {
			READ_LENGTH = ASN1InputStream.class.getDeclaredMethod("readLength", InputStream.class, int.class);
			READ_LENGTH.setAccessible(true);
		} catch (NoSuchMethodException | SecurityException e) {
			throw new RuntimeException("Unable to access to ASN1InputStream.readLength method", e);
		}

		try {
			READ_TAG_NUMBER = ASN1InputStream.class.getDeclaredMethod("readTagNumber", InputStream.class, int.class);
			READ_TAG_NUMBER.setAccessible(true);
		} catch (NoSuchMethodException | SecurityException e) {
			throw new RuntimeException("Unable to access to ASN1InputStream.readTagNumber method", e);
		}

	}

	private DERUtil() {
	}

	public static int readTag(InputStream is) throws IOException {
		return is.read();
	}

	public static int readLength(InputStream s) throws IOException {
		try {
			return (int) READ_LENGTH.invoke(null, s, Integer.MAX_VALUE);
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException("Unable to call to ASN1InputStream.readLength method", e);
		}
	}

	public static int readTagNumber(InputStream s, int tag) throws IOException {
		try {
			return (int) READ_TAG_NUMBER.invoke(null, s, tag);
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException("Unable to call to ASN1InputStream.readTagNumber method", e);
		}
	}

	/**
	 * Adaptation from org.bouncycastle.asn1.ASN1OutputStream.writeLength(int)
	 * 
	 * @param os
	 *            the output stream
	 * @param length
	 *            the length to add
	 * @throws IOException
	 */
	public static void writeLength(OutputStream os, int length) throws IOException {
		if (length > 127) {
			int size = 1;
			int val = length;

			while ((val >>>= 8) != 0) {
				size++;
			}

			os.write((byte) (size | 0x80));

			for (int i = (size - 1) * 8; i >= 0; i -= 8) {
				os.write((byte) (length >> i));
			}
		} else {
			os.write((byte) length);
		}
	}

}
