/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERT61UTF8String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.utils.Base64;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;

public final class DSSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSUtils.class);

	public static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----\n";
	public static final String CERT_END = "-----END CERTIFICATE-----";

	private static final BouncyCastleProvider securityProvider = new BouncyCastleProvider();

	/**
	 * Used to build output as Hex
	 */
	private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	/**
	 * Used to build output as Hex
	 */
	private static final char[] DIGITS_UPPER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	/**
	 * FROM: Apache
	 * The index value when an element is not found in a list or array: {@code -1}.
	 * This value is returned by methods in this class and can also be used in comparisons with values returned by
	 * various method from {@link java.util.List}.
	 */
	public static final int INDEX_NOT_FOUND = -1;

	/**
	 * The empty String {@code ""}.
	 *
	 * @since 2.0
	 */
	public static final String EMPTY = "";

	/**
	 * <p>The maximum size to which the padding constant(s) can expand.</p>
	 */
	private static final int PAD_LIMIT = 8192;

	private static final CertificateFactory certificateFactory;
	public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

	/**
	 * This date is used in the deterministic identifier computation when the signing time is unknown.
	 */
	private static final Date deterministicDate = DSSUtils.getUtcDate(1970, 04, 23);

	private static MessageDigest sha1Digester;

	private static JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

	static {

		try {

			Security.addProvider(securityProvider);

			certificateFactory = CertificateFactory.getInstance("X.509", "BC");

			sha1Digester = getMessageDigest(DigestAlgorithm.SHA1);

			jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
			jcaDigestCalculatorProviderBuilder.setProvider("BC");

		} catch (CertificateException e) {

			LOG.error(e.toString());
			throw new DSSException("Platform does not support X509 certificate", e);
		} catch (NoSuchProviderException e) {

			LOG.error(e.toString());
			throw new DSSException("Platform does not support BouncyCastle", e);
		} catch (NoSuchAlgorithmException e) {

			LOG.error(e.toString());
			throw new DSSException("The digest algorithm is not supported", e);
		}
	}

	/**
	 * The default buffer size to use.
	 */
	private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

	/**
	 * This class is an utility class and cannot be instantiated.
	 */
	private DSSUtils() {
	}

	/**
	 * Formats a date to use for internal purposes (logging, toString)
	 *
	 * @param date the date to be converted
	 * @return the textual representation (a null date will result in "N/A")
	 */
	public static String formatInternal(final Date date) {

		final String formatedDate = (date == null) ? "N/A" : new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(date);
		return formatedDate;
	}

	/**
	 * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
	 * String will be double the length of the passed array, as it takes two characters to represent any given byte. If
	 * the input array is null then null is returned. The obtained string is converted to uppercase.
	 *
	 * @param value
	 * @return
	 */
	public static String toHex(final byte[] value) {

		return (value != null) ? new String(encodeHex(value, false)) : null;
	}

	/**
	 * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
	 * String will be double the length of the passed array, as it takes two characters to represent any given byte.
	 *
	 * @param data a byte[] to convert to Hex characters
	 * @return A String containing hexadecimal characters
	 * @since 1.4
	 */
	public static String encodeHexString(byte[] data) {
		return new String(encodeHex(data));
	}

	/**
	 * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
	 * The returned array will be double the length of the passed array, as it takes two characters to represent any
	 * given byte.
	 *
	 * @param data a byte[] to convert to Hex characters
	 * @return A char[] containing hexadecimal characters
	 */
	public static char[] encodeHex(byte[] data) {
		return encodeHex(data, true);
	}

	/**
	 * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
	 * The returned array will be double the length of the passed array, as it takes two characters to represent any
	 * given byte.
	 *
	 * @param data        a byte[] to convert to Hex characters
	 * @param toLowerCase <code>true</code> converts to lowercase, <code>false</code> to uppercase
	 * @return A char[] containing hexadecimal characters
	 * @since 1.4
	 */
	public static char[] encodeHex(byte[] data, boolean toLowerCase) {
		return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
	}

	/**
	 * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
	 * The returned array will be double the length of the passed array, as it takes two characters to represent any
	 * given byte.
	 *
	 * @param data     a byte[] to convert to Hex characters
	 * @param toDigits the output alphabet
	 * @return A char[] containing hexadecimal characters
	 * @since 1.4
	 */
	protected static char[] encodeHex(byte[] data, char[] toDigits) {
		int l = data.length;
		char[] out = new char[l << 1];
		// two characters form the hex value.
		for (int i = 0, j = 0; i < l; i++) {
			out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
			out[j++] = toDigits[0x0F & data[i]];
		}
		return out;
	}

	/**
	 * Converts an array of characters representing hexadecimal values into an array of bytes of those same values. The
	 * returned array will be half the length of the passed array, as it takes two characters to represent any given
	 * byte. An exception is thrown if the passed char array has an odd number of elements.
	 *
	 * @param data An array of characters containing hexadecimal digits
	 * @return A byte array containing binary data decoded from the supplied char array.
	 * @throws DSSException Thrown if an odd number or illegal of characters is supplied
	 */
	public static byte[] decodeHex(char[] data) throws DSSException {

		int len = data.length;

		if ((len & 0x01) != 0) {
			throw new DSSException("Odd number of characters.");
		}

		byte[] out = new byte[len >> 1];

		// two characters form the hex value.
		for (int i = 0, j = 0; j < len; i++) {
			int f = toDigit(data[j], j) << 4;
			j++;
			f = f | toDigit(data[j], j);
			j++;
			out[i] = (byte) (f & 0xFF);
		}

		return out;
	}

	/**
	 * Converts a hexadecimal character to an integer.
	 *
	 * @param ch    A character to convert to an integer digit
	 * @param index The index of the character in the source
	 * @return An integer
	 * @throws DSSException Thrown if ch is an illegal hex character
	 */
	protected static int toDigit(char ch, int index) throws DSSException {
		int digit = Character.digit(ch, 16);
		if (digit == -1) {
			throw new DSSException("Illegal hexadecimal character " + ch + " at index " + index);
		}
		return digit;
	}

	/**
	 * Decodes a Base64 String into bytes.
	 *
	 * @param base64String
	 * @return
	 */
	public static byte[] base64Decode(final String base64String) throws DSSException {

		return Base64.decodeBase64(base64String);
	}

	/**
	 * Decodes a Base64 String into bytes.
	 *
	 * @param binaryData
	 * @return
	 */
	public static byte[] base64Decode(final byte[] binaryData) {

		return Base64.decodeBase64(binaryData);
	}

	/**
	 * Encodes binary data using the base64 algorithm but does not chunk the output. NOTE: We changed the behaviour of
	 * this method from multi-line chunking (commons-codec-1.4) to single-line non-chunking (commons-codec-1.5).
	 *
	 * @param binaryData
	 * @return
	 */
	public static String base64Encode(final byte[] binaryData) {

		return Base64.encodeBase64String(binaryData);
	}

	/**
	 * Encodes binary data using the base64 algorithm but does not chunk the output.
	 *
	 * @param binaryData
	 * @return
	 */
	public static byte[] base64BinaryEncode(final byte[] binaryData) {

		return Base64.encodeBase64(binaryData);
	}

	/**
	 * This method re-encode base 64 encoded string to base 64 encoded byte array.
	 *
	 * @param base64String
	 * @return
	 */
	public static byte[] base64StringToBase64Binary(final String base64String) {

		final byte[] decodedBase64 = Base64.decodeBase64(base64String);
		final byte[] encodeBase64 = Base64.encodeBase64(decodedBase64);
		return encodeBase64;
	}

	/**
	 * Encodes dss document using the base64 algorithm .
	 *
	 * @param dssDocument dss document to be encoded
	 * @return encoded base64 string
	 */
	public static String base64Encode(DSSDocument dssDocument) {

		final byte[] bytes = dssDocument.getBytes();
		final String base64EncodedBytes = base64Encode(bytes);
		return base64EncodedBytes;
	}

	/**
	 * @param certificate
	 * @return
	 */
	public static String base64Encode(final X509Certificate certificate) throws DSSException {

		try {
			final byte[] bytes = certificate.getEncoded();
			final String base64EncodedBytes = base64Encode(bytes);
			return base64EncodedBytes;
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * FROM: Apache IOUtils
	 * Get the contents of an {@code InputStream} as a String
	 * using the default character encoding of the platform.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a
	 * {@code BufferedInputStream}.
	 *
	 * @param input the {@code InputStream} to read from
	 * @return the requested String
	 * @throws NullPointerException if the input is null
	 * @throws DSSException         if an I/O error occurs
	 */
	public static String toString(InputStream input) throws DSSException {

		StringWriter sw = new StringWriter();
		copy(input, sw);
		return sw.toString();
	}

	/**
	 * FROM: Apache IOUtils
	 * Get the contents of an {@code InputStream} as a String using the specified character encoding.
	 * <p/>
	 * Character encoding names can be found at <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a {@code BufferedInputStream}.
	 *
	 * @param input    the {@code InputStream} to read from
	 * @param encoding the encoding to use, null means platform default
	 * @return the requested String
	 * @throws NullPointerException if the input is null
	 * @throws java.io.IOException  if an I/O error occurs
	 */
	public static String toString(InputStream input, String encoding) throws DSSException {

		StringWriter sw = new StringWriter();
		copy(input, sw, encoding);
		return sw.toString();
	}

	/**
	 * FROM: Apache IOUtils
	 * Copy bytes from an {@code InputStream} to chars on a {@code Writer} using the specified character
	 * encoding.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a {@code BufferedInputStream}.
	 * <p/>
	 * Character encoding names can be found at <a href="http://www.iana.org/assignments/character-sets">IANA</a>.
	 * <p/>
	 * This method uses {@link java.io.InputStreamReader}.
	 *
	 * @param input    the {@code InputStream} to read from
	 * @param output   the {@code Writer} to write to
	 * @param encoding the encoding to use, null means platform default
	 * @throws NullPointerException if the input or output is null
	 * @throws java.io.IOException  if an I/O error occurs
	 * @since Commons IO 1.1
	 */
	public static void copy(InputStream input, Writer output, String encoding) throws DSSException {
		try {
			if (encoding == null) {
				copy(input, output);
			} else {
				InputStreamReader in = new InputStreamReader(input, encoding);
				copy(in, output);
			}
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static void copy(InputStream input, Writer output) throws DSSException {

		InputStreamReader in = new InputStreamReader(input);
		copy(in, output);
	}

	/**
	 * FROM: Apache IOUtils
	 * Copy chars from a {@code Reader} to a {@code Writer}.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a {@code BufferedReader}.
	 * <p/>
	 * Large streams (over 2GB) will return a chars copied value of {@code -1} after the copy has completed since
	 * the correct number of chars cannot be returned as an int. For large streams use the
	 * {@code copyLarge(Reader, Writer)} method.
	 *
	 * @param input  the {@code Reader} to read from
	 * @param output the {@code Writer} to write to
	 * @return the number of characters copied
	 * @throws NullPointerException if the input or output is null
	 * @throws java.io.IOException  if an I/O error occurs
	 * @throws ArithmeticException  if the character count is too large
	 * @since Commons IO 1.1
	 */
	public static int copy(Reader input, Writer output) throws DSSException {

		long count = copyLarge(input, output);
		if (count > Integer.MAX_VALUE) {
			return -1;
		}
		return (int) count;
	}

	/**
	 * FROM: Apache IOUtils
	 * Copy chars from a large (over 2GB) {@code Reader} to a {@code Writer}.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a {@code BufferedReader}.
	 *
	 * @param input  the {@code Reader} to read from
	 * @param output the {@code Writer} to write to
	 * @return the number of characters copied
	 * @throws NullPointerException if the input or output is null
	 * @throws java.io.IOException  if an I/O error occurs
	 * @since Commons IO 1.3
	 */
	private
	static long copyLarge(Reader input, Writer output) throws DSSException {
		try {
			char[] buffer = new char[DEFAULT_BUFFER_SIZE];
			long count = 0;
			int n = 0;
			while (-1 != (n = input.read(buffer))) {
				output.write(buffer, 0, n);
				count += n;
			}
			return count;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * FROM: Apache IOUtils
	 * Copy bytes from an {@code InputStream} to an
	 * {@code OutputStream}.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a
	 * {@code BufferedInputStream}.
	 * <p/>
	 * Large streams (over 2GB) will return a bytes copied value of
	 * {@code -1} after the copy has completed since the correct
	 * number of bytes cannot be returned as an int. For large streams
	 * use the {@code copyLarge(InputStream, OutputStream)} method.
	 *
	 * @param input  the {@code InputStream} to read from
	 * @param output the {@code OutputStream} to write to
	 * @return the number of bytes copied
	 * @throws NullPointerException if the input or output is null
	 * @throws DSSException         if an I/O error occurs
	 * @throws ArithmeticException  if the byte count is too large
	 * @since Commons IO 1.1
	 */
	public static int copy(final InputStream input, final OutputStream output) throws DSSException {
		long count = copyLarge(input, output);
		if (count > Integer.MAX_VALUE) {
			return -1;
		}
		return (int) count;
	}

	/**
	 * FROM: Apache IOUtils
	 * Copy bytes from a large (over 2GB) {@code InputStream} to an
	 * {@code OutputStream}.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a
	 * {@code BufferedInputStream}.
	 *
	 * @param input  the {@code InputStream} to read from
	 * @param output the {@code OutputStream} to write to
	 * @return the number of bytes copied
	 * @throws NullPointerException if the input or output is null
	 * @throws DSSException         if an I/O error occurs
	 * @since Commons IO 1.3
	 */
	private static long copyLarge(InputStream input, OutputStream output) throws DSSException {

		try {
			byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
			long count = 0;
			int n = 0;
			while (-1 != (n = input.read(buffer))) {
				output.write(buffer, 0, n);
				count += n;
			}
			return count;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Writes bytes from a {@code byte[]} to an {@code OutputStream}.
	 *
	 * @param data   the byte array to write, do not modify during output,
	 *               null ignored
	 * @param output the {@code OutputStream} to write to
	 * @throws DSSException if output is null or an I/O error occurs
	 * @since Commons IO 1.1
	 */
	public static void write(byte[] data, OutputStream output) throws DSSException {

		try {
			if (data != null) {
				output.write(data);
			}
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method replaces all \ to /.
	 *
	 * @param path
	 * @return
	 */
	private static String normalisePath(String path) {

		return path.replace('\\', '/');
	}

	/**
	 * This method checks if the resource with the given path exists.
	 *
	 * @param path
	 * @return
	 */
	public static boolean resourceExists(final String path) {

		final String path_ = normalisePath(path);
		final URL url = DSSUtils.class.getResource(path_);
		return url != null;
	}

	/**
	 * This method checks if the file with the given path exists.
	 *
	 * @param path
	 * @return
	 */
	public static boolean fileExists(final String path) {

		final String path_ = normalisePath(path);
		final boolean exists = new File(path_).exists();
		return exists;
	}

	/**
	 * This method returns a file reference. The file path is normalised (OS independent)
	 *
	 * @param filePath The path to the file.
	 * @return
	 */
	public static File getFile(final String filePath) {

		final String normalisedFolderFileName = normalisePath(filePath);
		final File file = new File(normalisedFolderFileName);
		return file;
	}

	/**
	 * This method converts the given certificate into its PEM string.
	 *
	 * @param cert
	 * @return
	 * @throws java.security.cert.CertificateEncodingException
	 */
	public static String convertToPEM(final X509Certificate cert) throws DSSException {

		try {

			final Base64 encoder = new Base64(64);
			final byte[] derCert = cert.getEncoded();
			final String pemCertPre = new String(encoder.encode(derCert));
			final String pemCert = CERT_BEGIN + pemCertPre + CERT_END;
			return pemCert;
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads a certificate from the given resource.  The certificate must be DER-encoded and may be supplied in binary or printable
	 * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
	 * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null} when the
	 * certificate cannot be loaded.
	 *
	 * @param path resource location.
	 * @return
	 */
	public static X509Certificate loadCertificate(final String path) throws DSSException {

		final InputStream inputStream = DSSUtils.class.getResourceAsStream(path);
		return loadCertificate(inputStream);
	}

	/**
	 * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied in binary or printable
	 * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
	 * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null} when the
	 * certificate cannot be loaded.
	 *
	 * @param file
	 * @return
	 */
	public static X509Certificate loadCertificate(final File file) throws DSSException {

		final InputStream inputStream = DSSUtils.toByteArrayInputStream(file);
		final X509Certificate x509Certificate = loadCertificate(inputStream);
		return x509Certificate;
	}

	/**
	 * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied in binary or printable (Base64) encoding. If the
	 * certificate
	 * is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----. It throws
	 * an
	 * {@code DSSException} or return {@code null} when the certificate cannot be loaded.
	 *
	 * @param inputStream input stream containing the certificate
	 * @return
	 */
	public static X509Certificate loadCertificate(final InputStream inputStream) throws DSSException {

		try {

			final X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
			return cert;
		} catch (CertificateException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads a certificate from the byte array. The certificate must be DER-encoded and may be supplied in binary or printable
	 * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----, and
	 * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null} when the
	 * certificate cannot be loaded.
	 *
	 * @param input array of bytes containing the certificate
	 * @return
	 */
	public static X509Certificate loadCertificate(final byte[] input) throws DSSException {

		if (input == null) {
			throw new DSSNullException(byte[].class, "X5009 certificate");
		}
		final ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
		return loadCertificate(inputStream);
	}

	/**
	 * This method loads a certificate from a base 64 encoded String
	 *
	 * @param base64Encoded
	 * @return
	 */
	public static X509Certificate loadCertificateFromBase64EncodedString(final String base64Encoded) {

		final byte[] bytes = DSSUtils.base64Decode(base64Encoded);
		return loadCertificate(bytes);
	}

	/**
	 * This method loads the issuer certificate from the given location (AIA).  The certificate must be DER-encoded and may be supplied in binary or
	 * printable (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN
	 * CERTIFICATE-----, and must be bounded at the end by -----END CERTIFICATE-----.  It throws an
	 * {@code DSSException} or return {@code null} when the certificate cannot be loaded.
	 *
	 * @param cert   certificate for which the issuer should be loaded
	 * @param loader the loader to use
	 * @return
	 */
	public static X509Certificate loadIssuerCertificate(final X509Certificate cert, final DataLoader loader) {

		final String url = getAccessLocation(cert, X509ObjectIdentifiers.id_ad_caIssuers);
		if (url == null) {
			LOG.info("There is no AIA extension for certificate download.");
			return null;
		}
		LOG.debug("Loading certificate from {}", url);
		if (loader == null) {
			throw new DSSNullException(DataLoader.class);
		}
		byte[] bytes = loader.get(url);
		if (bytes == null || bytes.length <= 0) {
			LOG.error("Unable to read data from {}.", url);
			return null;
		}
		final X509Certificate issuerCert = loadCertificate(bytes);
		if (issuerCert == null) {
			LOG.error("Unable to read data from {}.", url);
			return null;
		}
		if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
			LOG.info("There is AIA extension, but the issuer subject name and subject name does not match.");
			return null;
		}
		return issuerCert;
	}

	/**
	 * This method return SKI bytes from certificate or null.
	 *
	 * @param x509Certificate {@code X509Certificate}
	 * @return ski bytes from the given certificate
	 * @throws Exception
	 */
	public static byte[] getSki(final X509Certificate x509Certificate) throws DSSException {

		try {

			final byte[] skiBytesFromCert = XMLX509SKI.getSKIBytesFromCert(x509Certificate);
			return skiBytesFromCert;
		} catch (XMLSecurityException e) {
			return null;
		} catch (Exception e) {
			throw new DSSException(e);
		}
		//        try {
		//            final byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.14");
		//            if (extensionValue == null) {
		//                return null;
		//            }
		//            ASN1OctetString str = ASN1OctetString.getInstance(new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject());
		//            SubjectKeyIdentifier keyId = SubjectKeyIdentifier.getInstance(new ASN1InputStream(new ByteArrayInputStream(str.getOctets())).readObject());
		//            return keyId.getKeyIdentifier();
		//        } catch (IOException e) {
		//            throw new DSSException(e);
		//        }
	}

	private static String getAccessLocation(final X509Certificate certificate, final DERObjectIdentifier accessMethod) {

		try {

			final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(X509Extension.authorityInfoAccess.getId());
			if (null == authInfoAccessExtensionValue) {
				return null;
			}
		 /* Parse the extension */
			final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(authInfoAccessExtensionValue));
			final DEROctetString oct = (DEROctetString) (asn1InputStream.readObject());
			asn1InputStream.close();
			final ASN1InputStream asn1InputStream2 = new ASN1InputStream(oct.getOctets());
			final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(asn1InputStream2.readObject());
			asn1InputStream2.close();

			String accessLocation = null;
			final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
			for (final AccessDescription accessDescription : accessDescriptions) {

				// LOG.debug("access method: " + accessDescription.getAccessMethod());
				final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(accessMethod);
				if (!correctAccessMethod) {
					continue;
				}
				GeneralName gn = accessDescription.getAccessLocation();
				if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

					// LOG.debug("not a uniform resource identifier");
					continue;
				}
				final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
				accessLocation = str.getString();
				// The HTTP protocol is preferred.
				if (Protocol.isHttpUrl(accessLocation)) {
					// LOG.debug("access location: " + accessLocation);
					break;
				}
			}
			return accessLocation;
		} catch (final IOException e) {

			// we do nothing
			// LOG.("IO error: " + e.getMessage(), e);
		}
		return null;
	}

	/**
	 * This method loads a CRL from the given base 64 encoded string.
	 *
	 * @param base64Encoded
	 * @return
	 */
	public static X509CRL loadCRLBase64Encoded(final String base64Encoded) {

		final byte[] derEncoded = DSSUtils.base64Decode(base64Encoded);
		final X509CRL crl = loadCRL(new ByteArrayInputStream(derEncoded));
		return crl;
	}

	/**
	 * This method loads a CRL from the given location.
	 *
	 * @param byteArray
	 * @return
	 */
	public static X509CRL loadCRL(final byte[] byteArray) {

		final ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArray);
		final X509CRL crl = loadCRL(inputStream);
		return crl;
	}

	/**
	 * This method loads a CRL from the given location.
	 *
	 * @param inputStream
	 * @return
	 */
	public static X509CRL loadCRL(final InputStream inputStream) {

		try {

			final X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
			return crl;
		} catch (CRLException e) {

			throw new DSSException(e);
		}
	}

	/**
	 * This method loads an OCSP response from the given base 64 encoded string.
	 *
	 * @param base64Encoded base 64 encoded OCSP response
	 * @return {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp loadOCSPBase64Encoded(final String base64Encoded) {

		final byte[] derEncoded = DSSUtils.base64Decode(base64Encoded);
		try {

			final OCSPResp ocspResp = new OCSPResp(derEncoded);
			final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
			return basicOCSPResp;
		} catch (OCSPException e) {

			throw new DSSException(e);
		} catch (IOException e) {

			throw new DSSException(e);
		}
	}

	public static List<String> getPolicyIdentifiers(final X509Certificate cert) {

		final byte[] certificatePolicies = cert.getExtensionValue(X509Extension.certificatePolicies.getId());
		if (certificatePolicies == null) {

			return Collections.emptyList();
		}
		ASN1InputStream input = null;
		ASN1Sequence seq = null;
		try {

			input = new ASN1InputStream(certificatePolicies);
			final DEROctetString s = (DEROctetString) input.readObject();
			final byte[] content = s.getOctets();
			input.close();
			input = new ASN1InputStream(content);
			seq = (ASN1Sequence) input.readObject();
		} catch (IOException e) {

			throw new DSSException("Error when computing certificate's extensions.", e);
		} finally {

			closeQuietly(input);
		}
		final List<String> policyIdentifiers = new ArrayList<String>();
		for (int ii = 0; ii < seq.size(); ii++) {

			final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
			// System.out.println("\t----> PolicyIdentifier: " + policyInfo.getPolicyIdentifier().getId());
			policyIdentifiers.add(policyInfo.getPolicyIdentifier().getId());

		}
		return policyIdentifiers;
	}

	/**
	 * This method converts the {@code List} of {@code CertificateToken} to the {@code List} of {@code X509Certificate}.
	 *
	 * @param certTokens the list of {@code CertificateToken} to be converted
	 * @return a list for {@code X509Certificate} based on the input list
	 */
	public static List<X509Certificate> getX509Certificates(final List<CertificateToken> certTokens) {

		final List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();
		for (final CertificateToken token : certTokens) {

			certificateChain.add(token.getCertificate());
		}
		return certificateChain;

	}

	/**
	 * This method digests the given string with SHA1 algorithm and encode returned array of bytes as hex string.
	 *
	 * @param stringToDigest Everything in the name
	 * @return hex encoded digest value
	 */
	public static String getSHA1Digest(final String stringToDigest) {

		final byte[] digest = sha1Digester.digest(stringToDigest.getBytes());
		return encodeHexString(digest);
	}

	/**
	 * This method digests the given {@code InputStream} with SHA1 algorithm and encode returned array of bytes as hex string.
	 *
	 * @param inputStream
	 * @return
	 */
	public static String getSHA1Digest(final InputStream inputStream) {

		final byte[] bytes = DSSUtils.toByteArray(inputStream);
		final byte[] digest = sha1Digester.digest(bytes);
		return encodeHexString(digest);
	}

	/**
	 * This method replaces in a string one pattern by another one without using regexp.
	 *
	 * @param string
	 * @param oldPattern
	 * @param newPattern
	 * @return
	 */
	public static StringBuffer replaceStrStr(final StringBuffer string, final String oldPattern, final String newPattern) {

		if (string == null || oldPattern == null || oldPattern.equals("") || newPattern == null) {

			return string;
		}

		final StringBuffer replaced = new StringBuffer();
		int startIdx = 0;
		int idxOld;
		while ((idxOld = string.indexOf(oldPattern, startIdx)) >= 0) {

			replaced.append(string.substring(startIdx, idxOld));
			replaced.append(newPattern);
			startIdx = idxOld + oldPattern.length();
		}
		replaced.append(string.substring(startIdx));
		return replaced;
	}

	public static String replaceStrStr(final String string, final String oldPattern, final String newPattern) {

		final StringBuffer stringBuffer = replaceStrStr(new StringBuffer(string), oldPattern, newPattern);
		return stringBuffer.toString();
	}

	/**
	 * This method allows to digest the data with the given algorithm.
	 *
	 * @param digestAlgorithm the algorithm to use
	 * @param data            the data to digest
	 * @return digested array of bytes
	 */
	public static byte[] digest(final DigestAlgorithm digestAlgorithm, final byte[] data) throws DSSException {

		try {

			final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
			final byte[] digestValue = messageDigest.digest(data);
			return digestValue;
		} catch (NoSuchAlgorithmException e) {

			throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
		}
	}

	/**
	 * @param digestAlgorithm
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static MessageDigest getMessageDigest(final DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {

		// TODO-Bob (13/07/2014):  To be checked if the default implementation copes with RIPEMD160
		//		if (digestAlgorithm.equals(DigestAlgorithm.RIPEMD160)) {
		//
		//			final RIPEMD160Digest digest = new RIPEMD160Digest();
		//			final byte[] message = certificateToken.getEncoded();
		//			digest.update(message, 0, message.length);
		//			final byte[] digestValue = new byte[digest.getDigestSize()];
		//			digest.doFinal(digestValue, 0);
		//			recalculatedBase64DigestValue = DSSUtils.base64BinaryEncode(digestValue);
		//		} else {

		final String digestAlgorithmOid = digestAlgorithm.getOid().getId();
		// System.out.println(">>> " + digestAlgorithmOid);
		final MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithmOid);
		// System.out.println(">>> " + messageDigest.getProvider() + "/" + messageDigest.getClass().getName());
		return messageDigest;
	}

	/**
	 * This method allows to digest the data in the {@code InputStream} with the given algorithm.
	 *
	 * @param digestAlgo  the algorithm to use
	 * @param inputStream the data to digest
	 * @return digested array of bytes
	 */
	public static byte[] digest(final DigestAlgorithm digestAlgo, final InputStream inputStream) throws DSSException {

		try {

			final MessageDigest messageDigest = getMessageDigest(digestAlgo);
			final byte[] buffer = new byte[4096];
			int count = 0;
			while ((count = inputStream.read(buffer)) > 0) {

				messageDigest.update(buffer, 0, count);
			}
			final byte[] digestValue = messageDigest.digest();
			return digestValue;
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] digest(DigestAlgorithm digestAlgorithm, byte[]... data) {

		try {

			final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
			for (final byte[] bytes : data) {

				messageDigest.update(bytes);
			}
			final byte[] digestValue = messageDigest.digest();
			return digestValue;
		} catch (NoSuchAlgorithmException e) {

			throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
		}
	}

	/**
	 * This method digest and encrypt the given {@code InputStream} with indicated private key and signature algorithm. To find the signature object
	 * the list of registered security Providers, starting with the most preferred Provider is traversed.
	 * <p/>
	 * This method returns an array of bytes representing the signature value. Signature object that implements the specified signature algorithm. It traverses the list of
	 * registered security Providers, starting with the most preferred Provider. A new Signature object encapsulating the SignatureSpi implementation from the first Provider
	 * that supports the specified algorithm is returned. The {@code NoSuchAlgorithmException} exception is wrapped in a DSSException.
	 *
	 * @param javaSignatureAlgorithm signature algorithm under JAVA form.
	 * @param privateKey             private key to use
	 * @param stream                 the data to digest
	 * @return digested and encrypted array of bytes
	 */
	public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final InputStream stream) {

		try {

			LOG.debug("Signature Algorithm: " + javaSignatureAlgorithm);
			final Signature signature = Signature.getInstance(javaSignatureAlgorithm);

			signature.initSign(privateKey);
			final byte[] buffer = new byte[4096];
			int count = 0;
			while ((count = stream.read(buffer)) > 0) {

				signature.update(buffer, 0, count);
			}
			final byte[] signatureValue = signature.sign();
			return signatureValue;
		} catch (SignatureException e) {
			throw new DSSException(e);
		} catch (InvalidKeyException e) {
			throw new DSSException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method digest and encrypt the given {@code InputStream} with indicated private key and signature algorithm. To find the signature object
	 * the list of registered security Providers, starting with the most preferred Provider is traversed.
	 * <p/>
	 * This method returns an array of bytes representing the signature value. Signature object that implements the specified signature algorithm. It traverses the list of
	 * registered security Providers, starting with the most preferred Provider. A new Signature object encapsulating the SignatureSpi implementation from the first Provider
	 * that supports the specified algorithm is returned. The {@code NoSuchAlgorithmException} exception is wrapped in a DSSException.
	 *
	 * @param javaSignatureAlgorithm signature algorithm under JAVA form.
	 * @param privateKey             private key to use
	 * @param bytes                  the data to digest
	 * @return digested and encrypted array of bytes
	 */
	public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final byte[] bytes) {

		try {

			final Signature signature = Signature.getInstance(javaSignatureAlgorithm);

			signature.initSign(privateKey);
			signature.update(bytes);
			final byte[] signatureValue = signature.sign();
			return signatureValue;
		} catch (SignatureException e) {
			throw new DSSException(e);
		} catch (InvalidKeyException e) {
			throw new DSSException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the {@code CertificateID} for the given certificate and its issuer's certificate.
	 *
	 * @param cert       {@code X509Certificate} for which the id is created
	 * @param issuerCert {@code X509Certificate} issuer certificate of the {@code cert}
	 * @return {@code CertificateID}
	 * @throws org.bouncycastle.cert.ocsp.OCSPException
	 */
	public static CertificateID getOCSPCertificateID(final X509Certificate cert, final X509Certificate issuerCert) throws DSSException {

		try {

			final BigInteger serialNumber = cert.getSerialNumber();
			final DigestCalculator digestCalculator = getSHA1DigestCalculator();
			final X509CertificateHolder x509CertificateHolder = getX509CertificateHolder(issuerCert);
			final CertificateID certificateID = new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
			return certificateID;
		} catch (OCSPException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns a {@code X509CertificateHolder} encapsulating the given {@code X509Certificate}.
	 *
	 * @param x509Certificate
	 * @return a X509CertificateHolder holding this certificate
	 */
	public static X509CertificateHolder getX509CertificateHolder(final X509Certificate x509Certificate) {

		try {
			return new X509CertificateHolder(x509Certificate.getEncoded());
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns a {@code X509CertificateHolder} encapsulating the given {@code CertificateToken}.
	 *
	 * @param certificateToken
	 * @return a X509CertificateHolder holding this certificate
	 */
	public static X509CertificateHolder getX509CertificateHolder(final CertificateToken certificateToken) {

		final X509CertificateHolder x509CertificateHolder = getX509CertificateHolder(certificateToken.getCertificate());
		return x509CertificateHolder;
	}

	public static DigestCalculator getSHA1DigestCalculator() throws DSSException {

		try {
			// final ASN1ObjectIdentifier oid = DigestAlgorithm.SHA1.getOid();
			// final DigestCalculator digestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(oid));

			final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
			final DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
			return digestCalculator;
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the encoded (as ASN.1 DER) form of this X.509 certificate.
	 *
	 * @param cert certificate
	 * @return encoded array of bytes
	 */
	public static byte[] getEncoded(final X509Certificate cert) {

		try {
			byte[] encoded = cert.getEncoded();
			return encoded;
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method opens the {@code URLConnection} using the given URL.
	 *
	 * @param url URL to be accessed
	 * @return {@code URLConnection}
	 */
	public static URLConnection openURLConnection(final String url) {

		try {

			final URL tspUrl = new URL(url);
			return tspUrl.openConnection();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static void writeToURLConnection(final URLConnection urlConnection, final byte[] bytes) throws DSSException {

		try {

			final OutputStream out = urlConnection.getOutputStream();
			out.write(bytes);
			out.close();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns an {@code InputStream} which does not need to be closed (based on {@code ByteArrayInputStream}.
	 *
	 * @param filePath The path to the file
	 * @return
	 * @throws DSSException
	 */
	public static InputStream toInputStream(final String filePath) throws DSSException {

		final File file = getFile(filePath);
		final InputStream inputStream = toByteArrayInputStream(file);
		return inputStream;
	}

	/**
	 * This method returns an {@code InputStream} which needs to be closed (based on {@code FileInputStream}.
	 *
	 * @param file {@code File} to read.
	 * @return {@code FileInputStream} representing the contents of the file.
	 * @throws DSSException
	 */
	public static InputStream toInputStream(final File file) throws DSSException {

		if (file == null) {

			throw new DSSNullException(File.class);
		}
		try {
			final FileInputStream fileInputStream = openInputStream(file);
			return fileInputStream;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns an {@code InputStream} which does not need to be closed (based on {@code ByteArrayInputStream}.
	 *
	 * @param file {@code File} to read
	 * @return {@code InputStream} based on {@code ByteArrayInputStream}
	 */
	public static InputStream toByteArrayInputStream(final File file) {

		if (file == null) {

			throw new DSSNullException(File.class);
		}
		try {
			final byte[] bytes = readFileToByteArray(file);
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
			return byteArrayInputStream;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param bytes
	 * @return
	 */
	public static InputStream toInputStream(byte[] bytes) {

		final InputStream inputStream = new ByteArrayInputStream(bytes);
		return inputStream;
	}

	/**
	 * @param string
	 * @param charset
	 * @return
	 */
	public static InputStream toInputStream(final String string, final String charset) throws DSSException {

		try {
			final InputStream inputStream = new ByteArrayInputStream(string.getBytes(charset));
			return inputStream;
		} catch (UnsupportedEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the byte array representing the contents of the file.
	 *
	 * @param file {@code File} to read.
	 * @return
	 * @throws DSSException
	 */
	public static byte[] toByteArray(final File file) throws DSSException {

		if (file == null) {

			throw new DSSNullException(File.class);
		}
		try {
			final byte[] bytes = readFileToByteArray(file);
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * FROM: Apache
	 * <p/>
	 * Reads the contents of a file into a byte array.
	 * The file is always closed.
	 *
	 * @param file the file to read, must not be {@code null}
	 * @return the file contents, never {@code null}
	 * @throws IOException in case of an I/O error
	 * @since Commons IO 1.1
	 */
	private static byte[] readFileToByteArray(File file) throws IOException {
		InputStream in = null;
		try {
			in = openInputStream(file);
			return toByteArray_(in);
		} finally {
			closeQuietly(in);
		}
	}

	/**
	 * FROM: Apache
	 * <p/>
	 * Opens a {@link java.io.FileInputStream} for the specified file, providing better
	 * error messages than simply calling {@code new FileInputStream(file)}.
	 * <p/>
	 * At the end of the method either the stream will be successfully opened,
	 * or an exception will have been thrown.
	 * <p/>
	 * An exception is thrown if the file does not exist.
	 * An exception is thrown if the file object exists but is a directory.
	 * An exception is thrown if the file exists but cannot be read.
	 *
	 * @param file the file to open for input, must not be {@code null}
	 * @return a new {@link java.io.FileInputStream} for the specified file
	 * @throws java.io.FileNotFoundException if the file does not exist
	 * @throws IOException                   if the file object is a directory
	 * @throws IOException                   if the file cannot be read
	 * @since Commons IO 1.3
	 */
	private static FileInputStream openInputStream(File file) throws IOException {
		if (file.exists()) {
			if (file.isDirectory()) {
				throw new IOException("File '" + file + "' exists but is a directory");
			}
			if (file.canRead() == false) {
				throw new IOException("File '" + file + "' cannot be read");
			}
		} else {
			throw new FileNotFoundException("File '" + file + "' does not exist");
		}
		return new FileInputStream(file);
	}

	/**
	 * Get the contents of an {@code InputStream} as a {@code byte[]}.
	 *
	 * @param inputStream
	 * @return
	 */
	public static byte[] toByteArray(final InputStream inputStream) {

		if (inputStream == null) {

			throw new DSSNullException(InputStream.class);
		}
		try {
			final byte[] bytes = toByteArray_(inputStream);
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * FROM: Apache
	 * Get the contents of an {@code InputStream} as a {@code byte[]}.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a
	 * {@code BufferedInputStream}.
	 *
	 * @param input the {@code InputStream} to read from
	 * @return the requested byte array
	 * @throws NullPointerException if the input is null
	 * @throws IOException          if an I/O error occurs
	 */
	private static byte[] toByteArray_(InputStream input) throws IOException {

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		copy(input, output);
		return output.toByteArray();
	}

	public static byte[] toByteArray(final String string) {

		return string.getBytes();
	}

	public static String toString(final byte[] bytes) {

		if (bytes == null) {

			throw new DSSNullException(byte[].class);
		}
		final String string = new String(bytes);
		return string;
	}

	public static void saveToFile(final byte[] bytes, final File file) throws DSSException {
		file.getParentFile().mkdirs();
		try {

			final FileOutputStream fos = new FileOutputStream(file);
			final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
			copy(inputStream, fos);
			closeQuietly(inputStream);
			closeQuietly(fos);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param certificate
	 * @return
	 */
	public static IssuerSerial getIssuerSerial(final X509Certificate certificate) {

		final X500Name issuerX500Name = DSSUtils.getX509CertificateHolder(certificate).getIssuer();
		final GeneralName generalName = new GeneralName(issuerX500Name);
		final GeneralNames generalNames = new GeneralNames(generalName);
		final BigInteger serialNumber = certificate.getSerialNumber();
		final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);
		return issuerSerial;
	}

	/**
	 * @param certificateToken
	 * @return
	 */
	public static IssuerSerial getIssuerSerial(final CertificateToken certificateToken) {

		final IssuerSerial issuerSerial = getIssuerSerial(certificateToken.getCertificate());
		return issuerSerial;
	}

	public static X509Certificate getCertificate(final X509CertificateHolder x509CertificateHolder) {

		try {

			final Certificate certificate = x509CertificateHolder.toASN1Structure();
			final X509CertificateObject x509CertificateObject = new X509CertificateObject(certificate);
			return x509CertificateObject;
		} catch (CertificateParsingException e) {
			throw new DSSException(e);
		}
	}

	public static X509CRL toX509CRL(final X509CRLHolder x509CRLHolder) {

		try {

			final JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
			final X509CRL x509CRL = jcaX509CRLConverter.getCRL(x509CRLHolder);
			return x509CRL;
		} catch (CRLException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] getEncoded(X509CRL x509CRL) {

		try {

			final byte[] encoded = x509CRL.getEncoded();
			return encoded;
		} catch (CRLException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] getEncoded(BasicOCSPResp basicOCSPResp) {

		try {
			final byte[] encoded = BasicOCSPResponse.getInstance(basicOCSPResp.getEncoded()).getEncoded(ASN1Encoding.DER);
			return encoded;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * return a unique id for a date and the certificateToken id.
	 *
	 * @param signingTime
	 * @param id
	 * @return
	 */
	public static String getDeterministicId(final Date signingTime, final int id) {

		final Calendar calendar = Calendar.getInstance();
		calendar.setTimeZone(TimeZone.getTimeZone("Z"));
		Date signingTime_ = signingTime;
		if (signingTime_ == null) {

			signingTime_ = deterministicDate;
		}
		calendar.setTime(signingTime_);

		final Date time = calendar.getTime();
		final long milliseconds = time.getTime();
		final long droppedMillis = 1000 * (milliseconds / 1000);

		final byte[] timeBytes = Long.toString(droppedMillis).getBytes();

		final ByteBuffer byteBuffer = ByteBuffer.allocate(4);
		byteBuffer.putInt(id);
		final byte[] certificateBytes = byteBuffer.array();

		final byte[] digestValue = DSSUtils.digest(DigestAlgorithm.MD5, timeBytes, certificateBytes);
		final String deterministicId = "id-" + toHex(digestValue);
		return deterministicId;
	}

	public static Date getLocalDate(final Date gtmDate, final Date localDate) {

		final Date newLocalDate = new Date(gtmDate.getTime() + TimeZone.getDefault().getOffset(localDate.getTime()));
		return newLocalDate;
	}

	public static long toLong(final byte[] bytes) {

		// Long.valueOf(new String(bytes)).longValue();
		ByteBuffer buffer = ByteBuffer.allocate(8);
		buffer.put(bytes, 0, Long.SIZE / 8);
		// TODO: (Bob: 2014 Jan 22) To be checked if it is not platform dependent?
		buffer.flip();//need flip
		return buffer.getLong();
	}

	public static void delete(final File file) {
		if (file != null) {
			file.delete();
		}
	}
	// Apache String Utils

	/**
	 * <p>Checks if a String is empty ("") or null.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.isEmpty(null)      = true
	 * DSSUtils.isEmpty("")        = true
	 * DSSUtils.isEmpty(" ")       = false
	 * DSSUtils.isEmpty("bob")     = false
	 * DSSUtils.isEmpty("  bob  ") = false
	 * </pre>
	 * <p/>
	 * <p>NOTE: This method changed in Lang version 2.0.
	 * It no longer trims the String.
	 * That functionality is available in isBlank().</p>
	 *
	 * @param str the String to check, may be null
	 * @return {@code true} if the String is empty or null
	 */
	public static boolean isEmpty(String str) {
		return str == null || str.length() == 0;
	}

	/**
	 * <p>Checks if a String is not empty ("") and not null.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.isNotEmpty(null)      = false
	 * DSSUtils.isNotEmpty("")        = false
	 * DSSUtils.isNotEmpty(" ")       = true
	 * DSSUtils.isNotEmpty("bob")     = true
	 * DSSUtils.isNotEmpty("  bob  ") = true
	 * </pre>
	 *
	 * @param str the String to check, may be null
	 * @return {@code true} if the String is not empty and not null
	 */
	public static boolean isNotEmpty(String str) {
		return !isEmpty(str);
	}

	/**
	 * <p>Compares two Strings, returning {@code true} if they are equal.</p>
	 * <p/>
	 * <p>{@code null}s are handled without exceptions. Two {@code null}
	 * references are considered to be equal. The comparison is case sensitive.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.equals(null, null)   = true
	 * DSSUtils.equals(null, "abc")  = false
	 * DSSUtils.equals("abc", null)  = false
	 * DSSUtils.equals("abc", "abc") = true
	 * DSSUtils.equals("abc", "ABC") = false
	 * </pre>
	 *
	 * @param str1 the first String, may be null
	 * @param str2 the second String, may be null
	 * @return {@code true} if the Strings are equal, case sensitive, or
	 * both {@code null}
	 * @see java.lang.String#equals(Object)
	 */
	public static boolean equals(String str1, String str2) {
		return str1 == null ? str2 == null : str1.equals(str2);
	}

	/**
	 * <p>Checks if a String is whitespace, empty ("") or null.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.isBlank(null)      = true
	 * DSSUtils.isBlank("")        = true
	 * DSSUtils.isBlank(" ")       = true
	 * DSSUtils.isBlank("bob")     = false
	 * DSSUtils.isBlank("  bob  ") = false
	 * </pre>
	 *
	 * @param str the String to check, may be null
	 * @return {@code true} if the String is null, empty or whitespace
	 * @since 2.0
	 */
	public static boolean isBlank(String str) {
		int strLen;
		if (str == null || (strLen = str.length()) == 0) {
			return true;
		}
		for (int i = 0; i < strLen; i++) {
			if ((Character.isWhitespace(str.charAt(i)) == false)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * <p>Checks if a String is not empty (""), not null and not whitespace only.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.isNotBlank(null)      = false
	 * DSSUtils.isNotBlank("")        = false
	 * DSSUtils.isNotBlank(" ")       = false
	 * DSSUtils.isNotBlank("bob")     = true
	 * DSSUtils.isNotBlank("  bob  ") = true
	 * </pre>
	 *
	 * @param str the String to check, may be null
	 * @return {@code true} if the String is
	 * not empty and not null and not whitespace
	 * @since 2.0
	 */
	public static boolean isNotBlank(String str) {
		return !isBlank(str);
	}

	// Apache Collection Utils

	/**
	 * <p>Checks if the object is in the given array.</p>
	 * <p/>
	 * <p>The method returns {@code false} if a {@code null} array is passed in.</p>
	 *
	 * @param array        the array to search through
	 * @param objectToFind the object to find
	 * @return {@code true} if the array contains the object
	 */
	public static boolean contains(Object[] array, Object objectToFind) {
		return indexOf(array, objectToFind) != INDEX_NOT_FOUND;
	}

	/**
	 * <p>Finds the index of the given object in the array.</p>
	 * <p/>
	 * <p>This method returns {@link #INDEX_NOT_FOUND} ({@code -1}) for a {@code null} input array.</p>
	 *
	 * @param array        the array to search through for the object, may be {@code null}
	 * @param objectToFind the object to find, may be {@code null}
	 * @return the index of the object within the array,
	 * {@link #INDEX_NOT_FOUND} ({@code -1}) if not found or {@code null} array input
	 */
	public static int indexOf(Object[] array, Object objectToFind) {
		return indexOf(array, objectToFind, 0);
	}

	/**
	 * <p>Finds the index of the given object in the array starting at the given index.</p>
	 * <p/>
	 * <p>This method returns {@link #INDEX_NOT_FOUND} ({@code -1}) for a {@code null} input array.</p>
	 * <p/>
	 * <p>A negative startIndex is treated as zero. A startIndex larger than the array
	 * length will return {@link #INDEX_NOT_FOUND} ({@code -1}).</p>
	 *
	 * @param array        the array to search through for the object, may be {@code null}
	 * @param objectToFind the object to find, may be {@code null}
	 * @param startIndex   the index to start searching at
	 * @return the index of the object within the array starting at the index,
	 * {@link #INDEX_NOT_FOUND} ({@code -1}) if not found or {@code null} array input
	 */
	public static int indexOf(Object[] array, Object objectToFind, int startIndex) {
		if (array == null) {
			return INDEX_NOT_FOUND;
		}
		if (startIndex < 0) {
			startIndex = 0;
		}
		if (objectToFind == null) {
			for (int i = startIndex; i < array.length; i++) {
				if (array[i] == null) {
					return i;
				}
			}
		} else if (array.getClass().getComponentType().isInstance(objectToFind)) {
			for (int i = startIndex; i < array.length; i++) {
				if (objectToFind.equals(array[i])) {
					return i;
				}
			}
		}
		return INDEX_NOT_FOUND;
	}

	/**
	 * Unconditionally close an {@code OutputStream}.
	 * <p/>
	 * Equivalent to {@link OutputStream#close()}, except any exceptions will be ignored.
	 * This is typically used in finally blocks.
	 *
	 * @param output the OutputStream to close, may be null or already closed
	 */
	public static void closeQuietly(OutputStream output) {
		try {
			if (output != null) {
				output.close();
			}
		} catch (IOException ioe) {
			// ignore
		}
	}

	/**
	 * Unconditionally close an {@code InputStream}.
	 * <p/>
	 * Equivalent to {@link InputStream#close()}, except any exceptions will be ignored.
	 * This is typically used in finally blocks.
	 *
	 * @param input the InputStream to close, may be null or already closed
	 */
	public static void closeQuietly(InputStream input) {
		try {
			if (input != null) {
				input.close();
			}
		} catch (IOException ioe) {
			// ignore
		}
	}

	/**
	 * Unconditionally close an {@code Reader}.
	 * <p/>
	 * Equivalent to {@link Reader#close()}, except any exceptions will be ignored.
	 * This is typically used in finally blocks.
	 *
	 * @param input the Reader to close, may be null or already closed
	 */
	public static void closeQuietly(Reader input) {
		try {
			if (input != null) {
				input.close();
			}
		} catch (IOException ioe) {
			// ignore
		}
	}

	/**
	 * Unconditionally close a {@code Writer}.
	 * <p/>
	 * Equivalent to {@link Writer#close()}, except any exceptions will be ignored.
	 * This is typically used in finally blocks.
	 *
	 * @param output the Writer to close, may be null or already closed
	 */
	public static void closeQuietly(Writer output) {
		try {
			if (output != null) {
				output.close();
			}
		} catch (IOException ioe) {
			// ignore
		}
	}

	/**
	 * Get the contents of an {@code InputStream} as a list of Strings,
	 * one entry per line, using the default character encoding of the platform.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a
	 * {@code BufferedInputStream}.
	 *
	 * @param input the {@code InputStream} to read from, not null
	 * @return the list of Strings, never null
	 * @throws NullPointerException if the input is null
	 * @throws DSSException         if an I/O error occurs
	 * @since Commons IO 1.1
	 */
	public static List readLines(InputStream input) throws DSSException {
		InputStreamReader reader = new InputStreamReader(input);
		return readLines(reader);
	}

	/**
	 * Get the contents of a {@code Reader} as a list of Strings,
	 * one entry per line.
	 * <p/>
	 * This method buffers the input internally, so there is no need to use a
	 * {@code BufferedReader}.
	 *
	 * @param input the {@code Reader} to read from, not null
	 * @return the list of Strings, never null
	 * @throws NullPointerException if the input is null
	 * @throws DSSException         if an I/O error occurs
	 * @since Commons IO 1.1
	 */
	public static List readLines(Reader input) throws DSSException {

		try {
			BufferedReader reader = new BufferedReader(input);
			List list = new ArrayList();
			String line = reader.readLine();
			while (line != null) {
				list.add(line);
				line = reader.readLine();
			}
			return list;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * <p>Joins the elements of the provided array into a single String
	 * containing the provided list of elements.</p>
	 * <p/>
	 * <p>No delimiter is added before or after the list.
	 * A {@code null} separator is the same as an empty String ("").
	 * Null objects or empty strings within the array are represented by
	 * empty strings.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.join(null, *)                = null
	 * DSSUtils.join([], *)                  = ""
	 * DSSUtils.join([null], *)              = ""
	 * DSSUtils.join(["a", "b", "c"], "--")  = "a--b--c"
	 * DSSUtils.join(["a", "b", "c"], null)  = "abc"
	 * DSSUtils.join(["a", "b", "c"], "")    = "abc"
	 * DSSUtils.join([null, "", "a"], ',')   = ",,a"
	 * </pre>
	 *
	 * @param array     the array of values to join together, may be null
	 * @param separator the separator character to use, null treated as ""
	 * @return the joined String, {@code null} if null array input
	 */
	public static String join(Object[] array, String separator) {
		if (array == null) {
			return null;
		}
		return join(array, separator, 0, array.length);
	}

	/**
	 * <p>Joins the elements of the provided {@code Collection} into
	 * a single String containing the provided elements.</p>
	 * <p/>
	 * <p>No delimiter is added before or after the list.
	 * A {@code null} separator is the same as an empty String ("").</p>
	 * <p/>
	 * <p>See the examples here: {@link #join(Object[], String)}. </p>
	 *
	 * @param collection the {@code Collection} of values to join together, may be null
	 * @param separator  the separator character to use, null treated as ""
	 * @return the joined String, {@code null} if null iterator input
	 * @since 2.3
	 */
	public static String join(Collection collection, String separator) {
		if (collection == null) {
			return null;
		}
		return join(collection.iterator(), separator);
	}

	/**
	 * <p>Joins the elements of the provided {@code Iterator} into
	 * a single String containing the provided elements.</p>
	 * <p/>
	 * <p>No delimiter is added before or after the list.
	 * A {@code null} separator is the same as an empty String ("").</p>
	 * <p/>
	 * <p>See the examples here: {@link #join(Object[], String)}. </p>
	 *
	 * @param iterator  the {@code Iterator} of values to join together, may be null
	 * @param separator the separator character to use, null treated as ""
	 * @return the joined String, {@code null} if null iterator input
	 */
	public static String join(Iterator iterator, String separator) {

		// handle null, zero and one elements before building a buffer
		if (iterator == null) {
			return null;
		}
		if (!iterator.hasNext()) {
			return EMPTY;
		}
		Object first = iterator.next();
		if (!iterator.hasNext()) {
			return toString(first);
		}

		// two or more elements
		StringBuilder buf = new StringBuilder(256); // Java default is 16, probably too small
		if (first != null) {
			buf.append(first);
		}

		while (iterator.hasNext()) {
			if (separator != null) {
				buf.append(separator);
			}
			Object obj = iterator.next();
			if (obj != null) {
				buf.append(obj);
			}
		}
		return buf.toString();
	}

	/**
	 * <p>Joins the elements of the provided array into a single String
	 * containing the provided list of elements.</p>
	 * <p/>
	 * <p>No delimiter is added before or after the list.
	 * A {@code null} separator is the same as an empty String ("").
	 * Null objects or empty strings within the array are represented by
	 * empty strings.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.join(null, *)                = null
	 * DSSUtils.join([], *)                  = ""
	 * DSSUtils.join([null], *)              = ""
	 * DSSUtils.join(["a", "b", "c"], "--")  = "a--b--c"
	 * DSSUtils.join(["a", "b", "c"], null)  = "abc"
	 * DSSUtils.join(["a", "b", "c"], "")    = "abc"
	 * DSSUtils.join([null, "", "a"], ',')   = ",,a"
	 * </pre>
	 *
	 * @param array      the array of values to join together, may be null
	 * @param separator  the separator character to use, null treated as ""
	 * @param startIndex the first index to start joining from.  It is
	 *                   an error to pass in an end index past the end of the array
	 * @param endIndex   the index to stop joining from (exclusive). It is
	 *                   an error to pass in an end index past the end of the array
	 * @return the joined String, {@code null} if null array input
	 */
	public static String join(Object[] array, String separator, int startIndex, int endIndex) {
		if (array == null) {
			return null;
		}
		if (separator == null) {
			separator = EMPTY;
		}

		// endIndex - startIndex > 0:   Len = NofStrings *(len(firstString) + len(separator))
		//           (Assuming that all Strings are roughly equally long)
		int bufSize = (endIndex - startIndex);
		if (bufSize <= 0) {
			return EMPTY;
		}

		bufSize *= ((array[startIndex] == null ? 16 : array[startIndex].toString().length()) + separator.length());

		StringBuilder buf = new StringBuilder(bufSize);

		for (int ii = startIndex; ii < endIndex; ii++) {
			if (ii > startIndex) {
				buf.append(separator);
			}
			if (array[ii] != null) {
				buf.append(array[ii]);
			}
		}
		return buf.toString();
	}

	/**
	 * <p>Gets the substring before the last occurrence of a separator.
	 * The separator is not returned.</p>
	 * <p/>
	 * <p>A {@code null} string input will return {@code null}.
	 * An empty ("") string input will return the empty string.
	 * An empty or {@code null} separator will return the input string.</p>
	 * <p/>
	 * <p>If nothing is found, the string input is returned.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.substringBeforeLast(null, *)      = null
	 * DSSUtils.substringBeforeLast("", *)        = ""
	 * DSSUtils.substringBeforeLast("abcba", "b") = "abc"
	 * DSSUtils.substringBeforeLast("abc", "c")   = "ab"
	 * DSSUtils.substringBeforeLast("a", "a")     = ""
	 * DSSUtils.substringBeforeLast("a", "z")     = "a"
	 * DSSUtils.substringBeforeLast("a", null)    = "a"
	 * DSSUtils.substringBeforeLast("a", "")      = "a"
	 * </pre>
	 *
	 * @param str       the String to get a substring from, may be null
	 * @param separator the String to search for, may be null
	 * @return the substring before the last occurrence of the separator,
	 * {@code null} if null String input
	 * @since 2.0
	 */
	public static String substringBeforeLast(String str, String separator) {
		if (isEmpty(str) || isEmpty(separator)) {
			return str;
		}
		int pos = str.lastIndexOf(separator);
		if (pos == INDEX_NOT_FOUND) {
			return str;
		}
		return str.substring(0, pos);
	}

	/**
	 * <p>Gets the substring after the last occurrence of a separator.
	 * The separator is not returned.</p>
	 * <p/>
	 * <p>A {@code null} string input will return {@code null}.
	 * An empty ("") string input will return the empty string.
	 * An empty or {@code null} separator will return the empty string if
	 * the input string is not {@code null}.</p>
	 * <p/>
	 * <p>If nothing is found, the empty string is returned.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.substringAfterLast(null, *)      = null
	 * DSSUtils.substringAfterLast("", *)        = ""
	 * DSSUtils.substringAfterLast(*, "")        = ""
	 * DSSUtils.substringAfterLast(*, null)      = ""
	 * DSSUtils.substringAfterLast("abc", "a")   = "bc"
	 * DSSUtils.substringAfterLast("abcba", "b") = "a"
	 * DSSUtils.substringAfterLast("abc", "c")   = ""
	 * DSSUtils.substringAfterLast("a", "a")     = ""
	 * DSSUtils.substringAfterLast("a", "z")     = ""
	 * </pre>
	 *
	 * @param str       the String to get a substring from, may be null
	 * @param separator the String to search for, may be null
	 * @return the substring after the last occurrence of the separator,
	 * {@code null} if null String input
	 * @since 2.0
	 */
	public static String substringAfterLast(String str, String separator) {
		if (isEmpty(str)) {
			return str;
		}
		if (isEmpty(separator)) {
			return EMPTY;
		}
		int pos = str.lastIndexOf(separator);
		if (pos == INDEX_NOT_FOUND || pos == (str.length() - separator.length())) {
			return EMPTY;
		}
		return str.substring(pos + separator.length());
	}

	/**
	 * <p>Repeat a String {@code repeat} times to form a
	 * new String.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.repeat(null, 2) = null
	 * DSSUtils.repeat("", 0)   = ""
	 * DSSUtils.repeat("", 2)   = ""
	 * DSSUtils.repeat("a", 3)  = "aaa"
	 * DSSUtils.repeat("ab", 2) = "abab"
	 * DSSUtils.repeat("a", -2) = ""
	 * </pre>
	 *
	 * @param str    the String to repeat, may be null
	 * @param repeat number of times to repeat str, negative treated as zero
	 * @return a new String consisting of the original String repeated,
	 * {@code null} if null String input
	 */
	public static String repeat(String str, int repeat) {
		// Performance tuned for 2.0 (JDK1.4)

		if (str == null) {
			return null;
		}
		if (repeat <= 0) {
			return EMPTY;
		}
		int inputLength = str.length();
		if (repeat == 1 || inputLength == 0) {
			return str;
		}
		if (inputLength == 1 && repeat <= PAD_LIMIT) {
			return padding(repeat, str.charAt(0));
		}

		int outputLength = inputLength * repeat;
		switch (inputLength) {
			case 1:
				char ch = str.charAt(0);
				char[] output1 = new char[outputLength];
				for (int i = repeat - 1; i >= 0; i--) {
					output1[i] = ch;
				}
				return new String(output1);
			case 2:
				char ch0 = str.charAt(0);
				char ch1 = str.charAt(1);
				char[] output2 = new char[outputLength];
				for (int i = repeat * 2 - 2; i >= 0; i--, i--) {
					output2[i] = ch0;
					output2[i + 1] = ch1;
				}
				return new String(output2);
			default:
				StringBuilder buf = new StringBuilder(outputLength);
				for (int i = 0; i < repeat; i++) {
					buf.append(str);
				}
				return buf.toString();
		}
	}

	/**
	 * <p>Returns padding using the specified delimiter repeated
	 * to a given length.</p>
	 * <p/>
	 * <pre>
	 * DSSUtils.padding(0, 'e')  = ""
	 * DSSUtils.padding(3, 'e')  = "eee"
	 * DSSUtils.padding(-2, 'e') = IndexOutOfBoundsException
	 * </pre>
	 * <p/>
	 * <p>Note: this method doesn't not support padding with
	 * <a href="http://www.unicode.org/glossary/#supplementary_character">Unicode Supplementary Characters</a>
	 * as they require a pair of {@code char}s to be represented.
	 * If you are needing to support full I18N of your applications
	 * consider using {@link #repeat(String, int)} instead.
	 * </p>
	 *
	 * @param repeat  number of times to repeat delim
	 * @param padChar character to repeat
	 * @return String with repeated character
	 * @throws DSSException if {@code repeat &lt; 0}
	 * @see #repeat(String, int)
	 */
	private static String padding(int repeat, char padChar) throws DSSException {
		if (repeat < 0) {
			throw new DSSException("Cannot pad a negative amount: " + repeat);
		}
		final char[] buf = new char[repeat];
		for (int i = 0; i < buf.length; i++) {
			buf[i] = padChar;
		}
		return new String(buf);
	}

	/**
	 * <p>Gets the {@code toString} of an {@code Object} returning
	 * an empty string ("") if {@code null} input.</p>
	 * <p/>
	 * <pre>
	 * ObjectUtils.toString(null)         = ""
	 * ObjectUtils.toString("")           = ""
	 * ObjectUtils.toString("bat")        = "bat"
	 * ObjectUtils.toString(Boolean.TRUE) = "true"
	 * </pre>
	 *
	 * @param obj the Object to {@code toString}, may be null
	 * @return the passed in Object's toString, or nullStr if {@code null} input
	 * @see String#valueOf(Object)
	 * @since 2.0
	 */
	public static String toString(Object obj) {

		return obj == null ? "" : obj.toString();
	}

	/**
	 * This method returns the {@code X500Principal} corresponding to the given string or {@code null} if the conversion is not possible.
	 *
	 * @param x500PrincipalString a {@code String} representation of the {@code X500Principal}
	 * @return {@code X500Principal} or null
	 */
	public static X500Principal getX500PrincipalOrNull(final String x500PrincipalString) {

		try {
			final X500Principal x500Principal = new X500Principal(x500PrincipalString);
			return x500Principal;
		} catch (Exception e) {
			LOG.warn(e.getMessage());
		}
		return null;
	}

	/**
	 * This method compares two {@code X500Principal}s. {@code X500Principal.CANONICAL} and {@code X500Principal.RFC2253} forms are compared.
	 * TODO: (Bob: 2014 Feb 20) To be investigated why the standard equals does not work!?
	 *
	 * @param firstX500Principal
	 * @param secondX500Principal
	 * @return
	 */
	public static boolean equals(final X500Principal firstX500Principal, final X500Principal secondX500Principal) {

		if (firstX500Principal == null || secondX500Principal == null) {
			return false;
		}
		if (firstX500Principal.equals(secondX500Principal)) {
			return true;
		}
		final HashMap<String, String> firstStringStringHashMap = get(firstX500Principal);
		final HashMap<String, String> secondStringStringHashMap = get(secondX500Principal);
		final boolean containsAll = firstStringStringHashMap.entrySet().containsAll(secondStringStringHashMap.entrySet());

		return containsAll;
	}

	/**
	 * @param x509SubjectName
	 * @return
	 */
	public static X500Principal getX500Principal(String x509SubjectName) throws DSSException {

		try {
			final X500Principal x500Principal = new X500Principal(x509SubjectName);
			final String utf8String = getUtf8String(x500Principal);
			final X500Principal normalizedX500Principal = new X500Principal(utf8String);
			return normalizedX500Principal;
		} catch (IllegalArgumentException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param x509Certificate
	 * @return
	 */
	public static X500Principal getSubjectX500Principal(final X509Certificate x509Certificate) {

		final X500Principal x500Principal = x509Certificate.getSubjectX500Principal();
		final String utf8Name = getUtf8String(x500Principal);
		// System.out.println(">>> " + x500Principal.getName() + "-------" + utf8Name);
		final X500Principal x500PrincipalNormalized = new X500Principal(utf8Name);
		return x500PrincipalNormalized;
	}


	/**
	 * @param x500Principal to be normalized
	 * @return {@code X500Principal} normalized
	 */
	public static X500Principal getX500Principal(final X500Principal x500Principal) {

		final String utf8Name = getUtf8String(x500Principal);
		final X500Principal x500PrincipalNormalized = new X500Principal(utf8Name);
		return x500PrincipalNormalized;
	}

	/**
	 * @param x509Certificate
	 * @return
	 */
	public static String getSubjectX500PrincipalName(final X509Certificate x509Certificate) {

		return getSubjectX500Principal(x509Certificate).getName();
	}

	/**
	 * The distinguished name is regenerated to avoid problems related to the {@code X500Principal} encoding.
	 *
	 * @param x509Certificate
	 * @return
	 */
	public static X500Principal getIssuerX500Principal(final X509Certificate x509Certificate) {

		final X500Principal x500Principal = x509Certificate.getIssuerX500Principal();
		final String utf8Name = getUtf8String(x500Principal);
		final X500Principal x500PrincipalNormalized = new X500Principal(utf8Name);
		return x500PrincipalNormalized;
	}

	/**
	 * @param x509Certificate
	 * @return
	 */
	public static String getIssuerX500PrincipalName(final X509Certificate x509Certificate) {

		return getIssuerX500Principal(x509Certificate).getName();
	}

	public static InputStream getResource(final String resourcePath) {

		final InputStream resourceAsStream = DSSUtils.class.getClassLoader().getResourceAsStream(resourcePath);
		return resourceAsStream;
	}

	/**
	 * This method returns an UTC date base on the year, the month and the day. The year must be encoded as 1978... and not 78
	 *
	 * @param year  the year
	 * @param month the month
	 * @param day   the day
	 * @return the UTC date base on parameters
	 */
	public static Date getUtcDate(final int year, final int month, final int day) {

		final Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.set(year, month, day, 0, 0, 0);
		final Date date = calendar.getTime();
		return date;
	}

	/**
	 * This method adds or subtract the given number of days from the date
	 *
	 * @param date {@code Date} to change
	 * @param days number of days (can be negative)
	 * @return new {@code Date}
	 */
	public static Date getDate(final Date date, int days) {

		final Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		calendar.add(Calendar.DATE, days);
		final Date newDate = calendar.getTime();
		return newDate;
	}

	/**
	 * Constructs a new <code>String</code> by decoding the specified array of bytes using the UTF-8 charset.
	 *
	 * @param bytes The bytes to be decoded into characters
	 * @return A new <code>String</code> decoded from the specified array of bytes using the UTF-8 charset,
	 * or <code>null</code> if the input byte array was <code>null</code>.
	 * @throws IllegalStateException Thrown when a {@link UnsupportedEncodingException} is caught, which should never happen since the
	 *                               charset is required.
	 */
	public static String getUtf8String(byte[] bytes) {

		if (bytes == null) {
			return null;
		}
		try {
			return new String(bytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param string
	 * @return
	 */
	public static String getUtf8String(final String string) {

		return getUtf8String(string.getBytes());
	}

	public static byte[] getUtf8Bytes(final String string) {

		if (string == null) {
			return null;
		}
		try {
			final byte[] bytes = string.getBytes("UTF-8");
			return bytes;
		} catch (UnsupportedEncodingException e) {
			throw new DSSException(e);
		}
	}

	private static HashMap<String, String> get(final X500Principal x500Principal) {

		HashMap<String, String> treeMap = new HashMap<String, String>();
		final byte[] encoded = x500Principal.getEncoded();
		final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(encoded);
		final ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
		for (final ASN1Encodable asn1Encodable : asn1Encodables) {

			final DLSet dlSet = (DLSet) asn1Encodable;
			for (int ii = 0; ii < dlSet.size(); ii++) {

				final DLSequence dlSequence = (DLSequence) dlSet.getObjectAt(ii);
				if (dlSequence.size() != 2) {

					throw new DSSException("The DLSequence must contains exactly 2 elements.");
				}
				final ASN1Encodable asn1EncodableAttributeType = dlSequence.getObjectAt(0);
				final String stringAttributeType = getString(asn1EncodableAttributeType);
				final ASN1Encodable asn1EncodableAttributeValue = dlSequence.getObjectAt(1);
				final String stringAttributeValue = getString(asn1EncodableAttributeValue);
				treeMap.put(stringAttributeType, stringAttributeValue);
			}
		}
		return treeMap;
	}

	private static String getUtf8String(final X500Principal x500Principal) {

		final byte[] encoded = x500Principal.getEncoded();
		final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(encoded);
		final ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
		final StringBuilder stringBuilder = new StringBuilder();
		/**
		 * RFC 4514 LDAP: Distinguished Names
		 * 2.1.  Converting the RDNSequence
		 *
		 * If the RDNSequence is an empty sequence, the result is the empty or
		 * zero-length string.
		 *
		 * Otherwise, the output consists of the string encodings of each
		 * RelativeDistinguishedName in the RDNSequence (according to Section
		 * 2.2), starting with the last element of the sequence and moving
		 * backwards toward the first.
		 * ...
		 */
		for (int ii = asn1Encodables.length - 1; ii >= 0; ii--) {

			final ASN1Encodable asn1Encodable = asn1Encodables[ii];

			final DLSet dlSet = (DLSet) asn1Encodable;
			for (int jj = 0; jj < dlSet.size(); jj++) {

				final DLSequence dlSequence = (DLSequence) dlSet.getObjectAt(jj);
				if (dlSequence.size() != 2) {

					throw new DSSException("The DLSequence must contains exactly 2 elements.");
				}
				final ASN1Encodable attributeType = dlSequence.getObjectAt(0);
				final ASN1Encodable attributeValue = dlSequence.getObjectAt(1);
				String string = getString(attributeValue);

				/**
				 * RFC 4514               LDAP: Distinguished Names
				 * ...
				 * Other characters may be escaped.
				 *
				 * Each octet of the character to be escaped is replaced by a backslash
				 * and two hex digits, which form a single octet in the code of the
				 * character.  Alternatively, if and only if the character to be escaped
				 * is one of
				 *
				 * ' ', '"', '#', '+', ',', ';', '<', '=', '>', or '\'
				 * (U+0020, U+0022, U+0023, U+002B, U+002C, U+003B,
				 * U+003C, U+003D, U+003E, U+005C, respectively)
				 *
				 * it can be prefixed by a backslash ('\' U+005C).
				 * ...
				 */
				string = string.replace("\"", "\\\"");
				string = string.replace("#", "\\#");
				string = string.replace("+", "\\+");
				string = string.replace(",", "\\,");
				string = string.replace(";", "\\;");
				string = string.replace("<", "\\<");
				string = string.replace("=", "\\=");
				string = string.replace(">", "\\>");
				// System.out.println(">>> " + attributeType.toString() + "=" + attributeValue.getClass().getSimpleName() + "[" + string + "]");
				if (stringBuilder.length() != 0) {
					stringBuilder.append(',');
				}
				stringBuilder.append(attributeType).append('=').append(string);
			}
		}
		//final X500Name x500Name = X500Name.getInstance(encoded);
		return stringBuilder.toString();
	}

	private static String getString(ASN1Encodable attributeValue) {
		String string;
		if (attributeValue instanceof DERUTF8String) {

			string = ((DERUTF8String) attributeValue).getString();
		} else if (attributeValue instanceof DERPrintableString) {

			string = ((DERPrintableString) attributeValue).getString();
		} else if (attributeValue instanceof DERBMPString) {

			string = ((DERBMPString) attributeValue).getString();
		} else if (attributeValue instanceof DERT61String) {

			string = ((DERT61String) attributeValue).getString();
		} else if (attributeValue instanceof DERIA5String) {

			string = ((DERIA5String) attributeValue).getString();
		} else if (attributeValue instanceof ASN1ObjectIdentifier) {

			string = ((ASN1ObjectIdentifier) attributeValue).getId();
		} else if (attributeValue instanceof DERT61UTF8String) {

			string = ((DERT61UTF8String) attributeValue).getString();
		} else {
			string = attributeValue.getClass().getSimpleName();
			LOG.error("!!!*******!!! This encoding is unknown: " + string);
		}
		return string;
	}

	/**
	 * This method return the unique message id which can be used for translation purpose.
	 *
	 * @param message the {@code String} message on which the unique id is calculated.
	 * @return the unique id
	 */
	public static String getMessageId(final String message) {

		final String message_ = message./*replace('\'', '_').*/toLowerCase().replaceAll("[^a-z_]", " ");
		StringBuilder nameId = new StringBuilder();
		final StringTokenizer stringTokenizer = new StringTokenizer(message_);
		while (stringTokenizer.hasMoreElements()) {

			final String word = (String) stringTokenizer.nextElement();
			nameId.append(word.charAt(0));
		}
		final String nameIdString = nameId.toString();
		return nameIdString.toUpperCase();
	}

	/**
	 * This method allows to convert the stack trace to a string.
	 *
	 * @param exception from which the stack trace should be extracted
	 * @return the exception's stack trace under the {@code String} form.
	 */
	public static String getStackTrace(final Exception exception) {

		final StringWriter stringWriter = new StringWriter();
		final PrintWriter printWriter = new PrintWriter(stringWriter);
		exception.printStackTrace(printWriter);
		return stringWriter.toString(); // stack trace as a string
	}

	/**
	 * Returns an estimate of the number of bytes that can be read (or
	 * skipped over) from this input stream without blocking by the next
	 * invocation of a method for this input stream. The next invocation
	 * might be the same thread or another thread.  A single read or skip of this
	 * many bytes will not block, but may read or skip fewer bytes.
	 * <p/>
	 * <p> Note that while some implementations of {@code InputStream} will return
	 * the total number of bytes in the stream, many will not.  It is
	 * never correct to use the return value of this method to allocate
	 * a buffer intended to hold all data in this stream.
	 * <p/>
	 * <p> A subclass' implementation of this method may choose to throw an
	 * {@link IOException} if this input stream has been closed by
	 * invoking the {@link InputStream#close()} method.
	 * <p/>
	 * <p> The {@code available} method for class {@code InputStream} always
	 * returns {@code 0}.
	 * <p/>
	 * <p> This method should be overridden by subclasses.
	 *
	 * @return an estimate of the number of bytes that can be read (or skipped
	 * over) from this input stream without blocking or {@code 0} when
	 * it reaches the end of the input stream.
	 * @throws DSSException if IOException occurs (if an I/O error occurs)
	 */
	public static int available(final InputStream is) throws DSSException {

		try {
			return is.available();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns <tt>true</tt> if the first {@code elementNumber} elements of the two specified arrays are
	 * <i>equal</i>.  Two arrays are considered equal if the first {@code elementNumber} corresponding pairs of elements in the two arrays are equal.
	 * Also, two array references are considered equal if both are <tt>null</tt>.<p>
	 *
	 * @param leftArray     one array to be tested for equality
	 * @param rightArray    the other array to be tested for equality
	 * @param elementNumber the number of elements from the beginning to be tested
	 * @return <tt>true</tt> if the two arrays are equal
	 */
	public static boolean equals(final byte[] leftArray, final byte[] rightArray, final int elementNumber) {

		if (leftArray == rightArray) {
			return true;
		}
		if (leftArray == null || rightArray == null) {
			return false;
		}
		if (leftArray == null && rightArray == null) {
			return true;
		}
		for (int ii = 0; ii < elementNumber; ii++) {

			if (leftArray[ii] != rightArray[ii]) {

				return false;
			}
		}
		return true;
	}


	/**
	 * replaces e.g. "\xc3\xa9" with "é"
	 *
	 * @param s the input
	 * @return the output
	 */
	public static String unescapeMultiByteUtf8Literals(final String s) {
		try {
			final String q = new String(unescapePython(s.getBytes("UTF-8")), "UTF-8");
			//			if (!q.equals(s)) {
			//				LOG.log(Level.SEVERE, "multi byte utf literal found:\n" +
			//							"  orig = " + s + "\n" +
			//							"  escp = " + q
			//				);
			//			}
			return q;
		} catch (Exception e) {
			//			LOG.log(Level.SEVERE, "Could not unescape multi byte utf literal - will use original input: " + s, e);
			return s;
		}
	}

	private static byte[] unescapePython(final byte[] escaped) throws Exception {
		// simple state machine iterates over the escaped bytes and converts
		final byte[] unescaped = new byte[escaped.length];
		int posTarget = 0;
		for (int posSource = 0; posSource < escaped.length; posSource++) {
			// if its not special then just move on
			if (escaped[posSource] != '\\') {
				unescaped[posTarget] = escaped[posSource];
				posTarget++;
				continue;
			}
			// if there is no next byte, throw incorrect encoding error
			if (posSource + 1 >= escaped.length) {
				throw new Exception("String incorrectly escaped, ends with escape character.");
			}
			// deal with hex first
			if (escaped[posSource + 1] == 'x') {
				// if there's no next byte, throw incorrect encoding error
				if (posSource + 3 >= escaped.length) {
					throw new Exception("String incorrectly escaped, ends early with incorrect hex encoding.");
				}
				unescaped[posTarget] = (byte) ((Character.digit(escaped[posSource + 2], 16) << 4) + Character.digit(escaped[posSource + 3], 16));
				posTarget++;
				posSource += 3;
			}
			// deal with n, then t, then r
			else if (escaped[posSource + 1] == 'n') {
				unescaped[posTarget] = '\n';
				posTarget++;
				posSource++;
			} else if (escaped[posSource + 1] == 't') {
				unescaped[posTarget] = '\t';
				posTarget++;
				posSource++;
			} else if (escaped[posSource + 1] == 'r') {
				unescaped[posTarget] = '\r';
				posTarget++;
				posSource++;
			} else if (escaped[posSource + 1] == '\\') {
				unescaped[posTarget] = escaped[posSource + 1];
				posTarget++;
				posSource++;
			} else if (escaped[posSource + 1] == '\'') {
				unescaped[posTarget] = escaped[posSource + 1];
				posTarget++;
				posSource++;
			} else {
				// invalid character
				throw new Exception("String incorrectly escaped, invalid escaped character");
			}
		}
		final byte[] result = new byte[posTarget];
		System.arraycopy(unescaped, 0, result, 0, posTarget);
		// return byte array, not string. Callers can convert to string.
		return result;
	}

	public static void copyFile(final String path, final File sourceFile, final File destinationFile) throws IOException {

		final File destinationPath = new File(path);
		if (!destinationPath.exists()) {
			destinationPath.mkdirs();
			destinationFile.createNewFile();
		}

		FileChannel source = null;
		FileChannel destination = null;

		try {
			source = new FileInputStream(sourceFile).getChannel();
			destination = new FileOutputStream(destinationFile).getChannel();
			destination.transferFrom(source, 0, source.size());
		} finally {
			if (source != null) {
				source.close();
			}
			if (destination != null) {
				destination.close();
			}
		}
	}

	public static byte[] toByteArray(final long longValue) {

		return String.valueOf(longValue).getBytes();
	}

	public static List<String> getQCStatementsIdList(final X509Certificate x509Certificate) {

		final List<String> extensionIdList = new ArrayList<String>();
		final byte[] qcStatement = x509Certificate.getExtensionValue(X509Extension.qCStatements.getId());
		if (qcStatement != null) {

			ASN1InputStream input = null;
			try {

				input = new ASN1InputStream(qcStatement);
				final DEROctetString s = (DEROctetString) input.readObject();
				final byte[] content = s.getOctets();
				input.close();
				input = new ASN1InputStream(content);
				final ASN1Sequence seq = (ASN1Sequence) input.readObject();
				/* Sequence of QCStatement */
				for (int ii = 0; ii < seq.size(); ii++) {

					final QCStatement statement = QCStatement.getInstance(seq.getObjectAt(ii));
					extensionIdList.add(statement.getStatementId().getId());
				}
			} catch (IOException e) {

				throw new DSSException(e);
			} finally {

				DSSUtils.closeQuietly(input);
			}
		}
		return extensionIdList;
	}

	/**
	 * This method closes the given {@code OutputStream} and throws a {@code DSSException} when the operation fails.
	 *
	 * @param outputStream {@code OutputStream} to be closed
	 */
	public static void close(final OutputStream outputStream) {

		try {
			outputStream.close();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the file extension based on the position of the '.' in the path. The paths as "xxx.y/toto" are not handled.
	 *
	 * @param path to be analysed
	 * @return the file extension or null
	 */
	public static String getFileExtension(final String path) {

		String extension = null;
		int lastIndexOf = path.lastIndexOf('.');
		if (lastIndexOf > 0) {
			extension = path.substring(lastIndexOf + 1);
		}
		return extension;
	}

	/**
	 * This method lists all defined secutity providers.
	 */
	public static void printSecurityProvides() {

		final Provider[] providers = Security.getProviders();
		for (final Provider provider : providers) {

			System.out.println("PROVIDER: " + provider.getName());
			final Set<Provider.Service> services = provider.getServices();
			for (final Provider.Service service : services) {

				System.out.println("\tALGORITHM: " + service.getAlgorithm() + " / " + service.getType() + " / " + service.getClassName());
			}
		}
	}
}

