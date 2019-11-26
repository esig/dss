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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1InputStream;

/**
 * This class is used to access to static methods of ASN1InputStream
 */
final class DERUtil {

	private DERUtil() {
	}

	public static int readTag(InputStream is) throws IOException {
		return is.read();
	}

	public static int readLength(InputStream s) throws IOException {
		try (ASN1InputStreamDSS dssIS = new ASN1InputStreamDSS(s, Integer.MAX_VALUE)) {
			return dssIS.readLength();
		}
	}

	/**
	 * Adaptation from org.bouncycastle.asn1.ASN1OutputStream.writeLength(int)
	 * 
	 * @param os     the output stream
	 * @param length the length to add
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

	/**
	 * 
	 * Copied from
	 * https://github.com/bcgit/bc-java/blob/r1rv63/core/src/main/java/org/bouncycastle/asn1/ASN1InputStream.java
	 * 
	 */
	public static int readTagNumber(InputStream s, int tag) throws IOException {
		int tagNo = tag & 0x1f;

		//
		// with tagged object tag number is bottom 5 bits, or stored at the start of the
		// content
		//
		if (tagNo == 0x1f) {
			tagNo = 0;

			int b = s.read();

			// X.690-0207 8.1.2.4.2
			// "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
			if ((b & 0x7f) == 0) // Note: -1 will pass
			{
				throw new IOException("corrupted stream - invalid high tag number found");
			}

			while ((b >= 0) && ((b & 0x80) != 0)) {
				tagNo |= (b & 0x7f);
				tagNo <<= 7;
				b = s.read();
			}

			if (b < 0) {
				throw new EOFException("EOF found inside tag value.");
			}

			tagNo |= (b & 0x7f);
		}

		return tagNo;
	}

	private static class ASN1InputStreamDSS extends ASN1InputStream {
		
		public ASN1InputStreamDSS(InputStream input, int limit) {
			super(input, limit);
		}
		
		@Override
		protected int readLength() throws IOException {
			return super.readLength();
		}

		@Override
		public void close() throws IOException {
			// not our job
		}

	}

}