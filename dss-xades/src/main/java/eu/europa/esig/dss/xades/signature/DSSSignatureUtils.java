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
package eu.europa.esig.dss.xades.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.BigIntegers;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.utils.Utils;

/**
 * This is the utility class to manipulate different signature types.
 *
 */
public final class DSSSignatureUtils {

	private DSSSignatureUtils() {
	}

	/**
	 * Converts the binary signature value to the Xml DSig format in function of used algorithm
	 *
	 * @param algorithm
	 *            Signature algorithm used to create the signatureValue
	 * @param signatureValue
	 * @return
	 */
	public static byte[] convertToXmlDSig(final EncryptionAlgorithm algorithm, byte[] signatureValue) {
		if (EncryptionAlgorithm.ECDSA == algorithm && isAsn1Encoded(signatureValue)) {
			return convertASN1toXMLDSIG(signatureValue);
		} else if (EncryptionAlgorithm.DSA == algorithm) {
			return convertASN1toXMLDSIG(signatureValue);
		} else {
			return signatureValue;
		}
	}

	/**
	 * Converts an ASN.1 value to a XML Signature Value.
	 *
	 * The JAVA JCE ECDSA/DSA Signature algorithm creates ASN.1 encoded (r,s) value pairs; the XML Signature requires
	 * the
	 * core BigInteger values.
	 *
	 * @param binaries
	 *            the ASN1 signature value
	 * @return the decode bytes
	 * @throws IOException
	 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
	 * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
	 */
	private static byte[] convertASN1toXMLDSIG(byte[] binaries) {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ASN1InputStream is = null;
		try {
			is = new ASN1InputStream(binaries);

			ASN1Sequence seq = (ASN1Sequence) is.readObject();
			if (seq.size() != 2) {
				throw new IllegalArgumentException("ASN1 Sequence size should be 2 !");
			}

			ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
			ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);

			byte[] rBytes = BigIntegers.asUnsignedByteArray(r.getValue());
			int rSize = rBytes.length;
			byte[] sBytes = BigIntegers.asUnsignedByteArray(s.getValue());
			int sSize = sBytes.length;
			int max = Math.max(rSize, sSize);
			max = max % 2 == 0 ? max : max + 1;
			leftPad(buffer, max, rBytes);
			buffer.write(rBytes);
			leftPad(buffer, max, sBytes);
			buffer.write(sBytes);

		} catch (Exception e) {
			throw new DSSException("Unable to convert to xmlDsig : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(is);
		}
		return buffer.toByteArray();
	}

	private static void leftPad(final ByteArrayOutputStream stream, final int size, final byte[] array) throws IOException {
		final int diff = size - array.length;
		if (diff > 0) {
			for (int i = 0; i < diff; i++) {
				stream.write(0x00);
			}
		}
	}

	/**
	 * Checks if the signature is ASN.1 encoded.
	 *
	 * @param signatureValue
	 *            signature value to check.
	 * @return if the signature is ASN.1 encoded.
	 */
	private static boolean isAsn1Encoded(byte[] signatureValue) {
		ASN1InputStream is = null;
		try {
			is = new ASN1InputStream(signatureValue);
			ASN1Primitive obj = is.readObject();
			return obj != null;
		} catch (IOException e) {
			return false;
		} finally {
			Utils.closeQuietly(is);
		}
	}

}
