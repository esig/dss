/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.crl.stream.impl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This class is used to replicate static methods of ASN1InputStream
 *
 */
final class DERUtil {

	/**
	 * Utils class
	 */
	private DERUtil() {
		// Empty
	}

	/**
	 * Reads the next tag if {@code InputStream}.
	 * The method does not close the InputStream.
	 *
	 * @param is {@link InputStream} to read
	 * @return integer
	 * @throws IOException if an exception occurs
	 */
	public static int readTag(InputStream is) throws IOException {
		return is.read();
	}

	/**
	 * Reads length of {@code InputStream}.
	 * The method does not close the InputStream.
	 * Adaptation from org.bouncycastle.asn1.ASN1InputStream.readLength(InputStream is)
	 *
	 * @param is {@link InputStream} to read
	 * @return length
	 * @throws IOException if an exception occurs on InputStream reading
	 * @throws EOFException if EOF is reached
	 */
	public static int readLength(InputStream is) throws IOException {
		// NOTE: ASN.1 fields are usually tiny, therefore one-byte-in-time reading is acceptable
		int length = is.read();
		if (0 == (length >>> 7)) {
			// definite-length short form
			return length;
		}
		if (0x80 == length) {
			// indefinite-length
			return -1;
		}
		if (length < 0) {
			throw new EOFException("EOF found when length expected");
		}
		if (0xFF == length) {
			throw new IOException("invalid long form definite-length 0xFF");
		}

		int octetsCount = length & 0x7F, octetsPos = 0;

		length = 0;
		do {
			int octet = is.read();
			if (octet < 0) {
				throw new EOFException("EOF found reading length");
			}
			if ((length >>> 23) != 0) {
				throw new IOException("long form definite-length more than 31 bits");
			}
			length = (length << 8) + octet;
		}
		while (++octetsPos < octetsCount);

		return length;
	}

	/**
	 * Adaptation from org.bouncycastle.asn1.ASN1OutputStream.writeLength(int)
	 * 
	 * @param os     {@link OutputStream}
	 * @param length the length to add
	 * @throws IOException if an error occurs during the OutputStream creation
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
	 * Reads the tag number
	 * <p>
	 * Copied from
	 * {@code <a href="https://github.com/bcgit/bc-java/blob/r1rv63/core/src/main/java/org/bouncycastle/asn1/ASN1InputStream.java">ASN1InputStream.java</a>}
	 *
	 * @param is {@link InputStream}
	 * @param tag the tag number to read
	 * @return tag number
	 * @throws IOException if an excsption occurs
	 */
	public static int readTagNumber(InputStream is, int tag) throws IOException {
		int tagNo = tag & 0x1f;

		//
		// with tagged object tag number is bottom 5 bits, or stored at the start of the
		// content
		//
		if (tagNo == 0x1f) {
			tagNo = 0;

			int b = is.read();

			// X.690-0207 8.1.2.4.2
			// "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
			if ((b & 0x7f) == 0) // Note: -1 will pass
			{
				throw new IOException("corrupted stream - invalid high tag number found");
			}

			while ((b >= 0) && ((b & 0x80) != 0)) {
				tagNo |= (b & 0x7f);
				tagNo <<= 7;
				b = is.read();
			}

			if (b < 0) {
				throw new EOFException("EOF found inside tag value.");
			}

			tagNo |= (b & 0x7f);
		}

		return tagNo;
	}

}