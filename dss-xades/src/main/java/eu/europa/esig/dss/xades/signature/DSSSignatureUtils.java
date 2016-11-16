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
			return convertECDSAASN1toXMLDSIG(signatureValue);
		} else if (EncryptionAlgorithm.DSA == algorithm) {
			return convertDSAASN1toXMLDSIG(signatureValue);
		} else {
			return signatureValue;
		}
	}

	/**
	 * Converts an ASN.1 ECDSA value to a XML Signature ECDSA Value.
	 *
	 * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r,s) value pairs; the XML Signature requires the
	 * core BigInteger values.
	 *
	 * @param binaries
	 *            the ASN1 signature value
	 * @return the decode bytes
	 * @throws IOException
	 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
	 * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
	 */
	private static byte[] convertECDSAASN1toXMLDSIG(byte[] binaries) {
		ASN1InputStream is = null;
		try {
			is = new ASN1InputStream(binaries);

			ASN1Sequence seq = (ASN1Sequence) is.readObject();
			if (seq.size() != 2) {
				throw new IllegalArgumentException("ASN1 Sequence size should be 2 !");
			}
			ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
			ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);

			byte[] rBytes = r.getValue().toByteArray();
			int rSize = rBytes.length;
			byte[] sBytes = s.getValue().toByteArray();
			int sSize = sBytes.length;

			int max = Math.max(rSize, sSize);

			ByteArrayOutputStream buffer = new ByteArrayOutputStream(max * 2);
			if (sSize > rSize) {
				buffer.write(0x00);
			}
			buffer.write(rBytes);
			if (rSize > sSize) {
				buffer.write(0x00);
			}
			buffer.write(sBytes);
			return buffer.toByteArray();
		} catch (Exception e) {
			throw new DSSException("Unable to convert to xmlDsig : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(is);
		}
	}

	/**
	 * Converts an ASN.1 DSA value to a XML Signature DSA Value.
	 *
	 * The JAVA JCE DSA Signature algorithm creates ASN.1 encoded (r,s) value pairs; the XML Signature requires the
	 * core BigInteger values.
	 *
	 * @param binaries
	 *            the ASN1 signature value
	 * @return the decode bytes
	 * @throws IOException
	 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
	 * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
	 */
	private static byte[] convertDSAASN1toXMLDSIG(byte[] binaries) {
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

			buffer.write(BigIntegers.asUnsignedByteArray(r.getValue()));
			buffer.write(BigIntegers.asUnsignedByteArray(s.getValue()));
		} catch (Exception e) {
			throw new DSSException("Unable to convert to xmlDsig : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(is);
		}
		return buffer.toByteArray();
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
