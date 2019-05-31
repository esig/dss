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
package eu.europa.esig.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public final class DSSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSUtils.class);

	private static final BouncyCastleProvider securityProvider = new BouncyCastleProvider();

	private static final CertificateFactory certificateFactory;

	public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

	public static final String DEFAULT_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/**
	 * The default date pattern: "yyyy-MM-dd"
	 */
	public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	static {
		try {
			Security.addProvider(securityProvider);
			certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException("Platform does not support X509 certificate", e);
		} catch (NoSuchProviderException e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException("Platform does not support BouncyCastle", e);
		}
	}

	/**
	 * This class is an utility class and cannot be instantiated.
	 */
	private DSSUtils() {
	}

	/**
	 * Formats a date to use for internal purposes (logging, toString)
	 *
	 * @param date
	 *            the date to be converted
	 * @return the textual representation (a null date will result in "N/A")
	 */
	public static String formatInternal(final Date date) {
		final String formatedDate = (date == null) ? "N/A" : new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT).format(date);
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
		return (value != null) ? Utils.toHex(value) : null;
	}

	/**
	 * This method converts the given certificate into its PEM string.
	 *
	 * @param cert
	 *            the token to be converted to PEM
	 * @return PEM encoded certificate
	 * @throws DSSException
	 */
	public static String convertToPEM(final CertificateToken cert) throws DSSException {
		return convertToPEM(cert.getCertificate());
	}

	/**
	 * This method converts the given CRL into its PEM string.
	 *
	 * @param crl
	 *            the DER encoded CRL to be converted
	 * 
	 * @return the PEM encoded CRL
	 */
	public static String convertCrlToPEM(final X509CRL crl) throws DSSException {
		return convertToPEM(crl);
	}

	private static String convertToPEM(Object obj) throws DSSException {
		try (StringWriter out = new StringWriter(); PemWriter pemWriter = new PemWriter(out)) {
			pemWriter.writeObject(new JcaMiscPEMGenerator(obj));
			pemWriter.flush();
			return out.toString();
		} catch (Exception e) {
			throw new DSSException("Unable to convert DER to PEM", e);
		}
	}

	/**
	 * This method returns true if the inputStream contains a DER encoded item
	 * 
	 * @return true if DER encoded
	 */
	public static boolean isDER(InputStream is) {
		byte firstByte = readFirstByte(new InMemoryDocument(is));
		return DSSASN1Utils.isASN1SequenceTag(firstByte);
	}

	/**
	 * This method converts a PEM encoded certificate/crl/... to DER encoded
	 * 
	 * @param pemContent
	 *            the String which contains the PEM encoded object
	 * @return the binaries of the DER encoded object
	 */
	public static byte[] convertToDER(String pemContent) {
		try (Reader reader = new StringReader(pemContent); PemReader pemReader = new PemReader(reader)) {
			PemObject readPemObject = pemReader.readPemObject();
			return readPemObject.getContent();
		} catch (IOException e) {
			throw new DSSException("Unable to convert PEM to DER", e);
		}
	}

	/**
	 * This method loads a certificate from the given resource. The certificate must be DER-encoded and may be supplied
	 * in binary or printable
	 * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 * -----BEGIN CERTIFICATE-----, and
	 * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null}
	 * when the
	 * certificate cannot be loaded.
	 *
	 * @param path
	 *            resource location.
	 * @return
	 */
	public static CertificateToken loadCertificate(final String path) throws DSSException {
		final InputStream inputStream = DSSUtils.class.getResourceAsStream(path);
		return loadCertificate(inputStream);
	}

	/**
	 * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied
	 * in binary or printable
	 * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 * -----BEGIN CERTIFICATE-----, and
	 * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null}
	 * when the
	 * certificate cannot be loaded.
	 *
	 * @param file
	 * @return
	 */
	public static CertificateToken loadCertificate(final File file) throws DSSException {
		final InputStream inputStream = DSSUtils.toByteArrayInputStream(file);
		final CertificateToken x509Certificate = loadCertificate(inputStream);
		return x509Certificate;
	}

	/**
	 * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied
	 * in binary or printable (Base64) encoding. If the
	 * certificate is provided in Base64 encoding, it must be bounded at the beginning by -----BEGIN CERTIFICATE-----,
	 * and must be bounded at the end by -----END CERTIFICATE-----.
	 * It throws an {@code DSSException} or return {@code null} when the certificate cannot be loaded.
	 *
	 * @param inputStream
	 *            input stream containing the certificate
	 * @return
	 */
	public static CertificateToken loadCertificate(final InputStream inputStream) throws DSSException {
		List<CertificateToken> certificates = loadCertificates(inputStream);
		if (certificates.size() == 1) {
			return certificates.get(0);
		}
		throw new DSSException("Could not parse certificate");
	}

	public static Collection<CertificateToken> loadCertificateFromP7c(InputStream is) {
		return loadCertificates(is);
	}

	private static List<CertificateToken> loadCertificates(InputStream is) {
		final List<CertificateToken> certificates = new ArrayList<CertificateToken>();
		try {
			@SuppressWarnings("unchecked")
			final Collection<X509Certificate> certificatesCollection = (Collection<X509Certificate>) certificateFactory.generateCertificates(is);
			if (certificatesCollection != null) {
				for (X509Certificate cert : certificatesCollection) {
					certificates.add(new CertificateToken(cert));
				}
			}
			if (certificates.isEmpty()) {
				throw new DSSException("Could not parse certificate(s)");
			}
			return certificates;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads a certificate from the byte array. The certificate must be DER-encoded and may be supplied in
	 * binary or printable
	 * (Base64) encoding. If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 * -----BEGIN CERTIFICATE-----, and
	 * must be bounded at the end by -----END CERTIFICATE-----. It throws an {@code DSSException} or return {@code null}
	 * when the
	 * certificate cannot be loaded.
	 *
	 * @param input
	 *            array of bytes containing the certificate
	 * @return
	 */
	public static CertificateToken loadCertificate(final byte[] input) throws DSSException {
		if (input == null) {
			throw new NullPointerException("X509 certificate");
		}
		try (ByteArrayInputStream inputStream = new ByteArrayInputStream(input)) {
			return loadCertificate(inputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads a certificate from a base 64 encoded String
	 *
	 * @param base64Encoded
	 * @return
	 */
	public static CertificateToken loadCertificateFromBase64EncodedString(final String base64Encoded) {
		final byte[] bytes = Utils.fromBase64(base64Encoded);
		return loadCertificate(bytes);
	}

	/**
	 * This method loads the potential issuer certificate(s) from the given locations (AIA).
	 * 
	 * @param cert
	 *            certificate for which the issuer(s) should be loaded
	 * @param loader
	 *            the data loader to use
	 * @return a list of potential issuers
	 */
	public static Collection<CertificateToken> loadPotentialIssuerCertificates(final CertificateToken cert, final DataLoader loader) {
		List<String> urls = DSSASN1Utils.getCAAccessLocations(cert);

		if (Utils.isCollectionEmpty(urls)) {
			LOG.info("There is no AIA extension for certificate download.");
			return Collections.emptyList();
		}
		if (loader == null) {
			LOG.warn("There is no DataLoader defined to load Certificates from AIA extension (urls : {})", urls);
			return Collections.emptyList();
		}

		for (String url : urls) {
			LOG.debug("Loading certificate(s) from {}", url);
			byte[] bytes = loader.get(url);
			if (Utils.isArrayNotEmpty(bytes)) {
				LOG.debug("Base64 content : {}", Utils.toBase64(bytes));
				try (InputStream is = new ByteArrayInputStream(bytes)) {
					return loadCertificates(is);
				} catch (Exception e) {
					LOG.warn("Unable to parse certificate(s) from AIA (url: {}) : {}", url, e.getMessage());
				}
			} else {
				LOG.warn("Empty content from {}.", url);
			}
		}

		return Collections.emptyList();
	}

	/**
	 * This method loads a CRL from the given location.
	 *
	 * @param inputStream
	 * @return
	 * @deprecated for performance reasons, the X509CRL object needs to be avoided
	 */
	@Deprecated
	public static X509CRL loadCRL(final InputStream inputStream) {
		try {
			return (X509CRL) certificateFactory.generateCRL(inputStream);
		} catch (CRLException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method digests the given string with SHA1 algorithm and encode returned array of bytes as hex string.
	 *
	 * @param stringToDigest
	 *            Everything in the name
	 * @return hex encoded digest value
	 */
	public static String getSHA1Digest(final String stringToDigest) {
		final byte[] digest = getMessageDigest(DigestAlgorithm.SHA1).digest(stringToDigest.getBytes());
		return Utils.toHex(digest);
	}

	/**
	 * This method allows to digest the data with the given algorithm.
	 *
	 * @param digestAlgorithm
	 *            the algorithm to use
	 * @param data
	 *            the data to digest
	 * @return digested array of bytes
	 */
	public static byte[] digest(final DigestAlgorithm digestAlgorithm, final byte[] data) throws DSSException {
		final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
		final byte[] digestValue = messageDigest.digest(data);
		return digestValue;
	}

	/**
	 * @param digestAlgorithm
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static MessageDigest getMessageDigest(final DigestAlgorithm digestAlgorithm) {
		try {
			final String digestAlgorithmOid = digestAlgorithm.getOid();
			final MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithmOid, BouncyCastleProvider.PROVIDER_NAME);
			return messageDigest;
		} catch (GeneralSecurityException e) {
			throw new DSSException("Digest algorithm '" + digestAlgorithm.getName() + "' error: " + e.getMessage(), e);
		}
	}

	/**
	 * This method allows to digest the data in the {@code InputStream} with the given algorithm.
	 *
	 * @param digestAlgo
	 *            the algorithm to use
	 * @param inputStream
	 *            the data to digest
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
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] digest(DigestAlgorithm digestAlgorithm, DSSDocument document) {
		try (InputStream is = document.openStream()) {
			return digest(digestAlgorithm, is);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] digest(DigestAlgorithm digestAlgorithm, byte[]... data) {
		final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
		for (final byte[] bytes : data) {

			messageDigest.update(bytes);
		}
		final byte[] digestValue = messageDigest.digest();
		return digestValue;
	}

	/**
	 * This method returns an {@code InputStream} which needs to be closed, based on {@code FileInputStream}.
	 *
	 * @param file
	 *            {@code File} to read.
	 * @return an {@code InputStream} materialized by a {@code FileInputStream} representing the contents of the file
	 * @throws DSSException
	 */
	public static InputStream toInputStream(final File file) throws DSSException {
		if (file == null) {
			throw new NullPointerException();
		}
		try {
			final FileInputStream fileInputStream = openInputStream(file);
			return fileInputStream;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns an {@code InputStream} which does not need to be closed, based on
	 * {@code ByteArrayInputStream}.
	 *
	 * @param file
	 *            {@code File} to read
	 * @return {@code InputStream} based on {@code ByteArrayInputStream}
	 */
	public static InputStream toByteArrayInputStream(final File file) {
		if (file == null) {
			throw new NullPointerException();
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
	 * This method returns the byte array representing the contents of the file.
	 *
	 * @param file
	 *            {@code File} to read
	 * @return an array of {@code byte}
	 * @throws DSSException
	 */
	public static byte[] toByteArray(final File file) throws DSSException {
		if (file == null) {
			throw new NullPointerException();
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
	 * Reads the contents of a file into a byte array.
	 * The file is always closed.
	 *
	 * @param file
	 *            the file to read, must not be {@code null}
	 * @return the file contents, never {@code null}
	 * @throws IOException
	 *             in case of an I/O error
	 * @since Commons IO 1.1
	 */
	private static byte[] readFileToByteArray(final File file) throws IOException {
		InputStream in = null;
		try {
			in = openInputStream(file);
			return Utils.toByteArray(in);
		} finally {
			Utils.closeQuietly(in);
		}
	}

	/**
	 * FROM: Apache
	 * Opens a {@link java.io.FileInputStream} for the specified file, providing better
	 * error messages than simply calling {@code new FileInputStream(file)}.
	 * At the end of the method either the stream will be successfully opened,
	 * or an exception will have been thrown.
	 * An exception is thrown if the file does not exist.
	 * An exception is thrown if the file object exists but is a directory.
	 * An exception is thrown if the file exists but cannot be read.
	 *
	 * @param file
	 *            the file to open for input, must not be {@code null}
	 * @return a new {@link java.io.FileInputStream} for the specified file
	 * @throws java.io.FileNotFoundException
	 *             if the file does not exist
	 * @throws IOException
	 *             if the file object is a directory
	 * @throws IOException
	 *             if the file cannot be read
	 * @since Commons IO 1.3
	 */
	private static FileInputStream openInputStream(final File file) throws IOException {
		if (file.exists()) {
			if (file.isDirectory()) {
				throw new IOException("File '" + file + "' exists but is a directory");
			}
			if (!file.canRead()) {
				throw new IOException("File '" + file + "' cannot be read");
			}
		} else {
			throw new FileNotFoundException("File '" + file + "' does not exist");
		}
		return new FileInputStream(file);
	}

	/**
	 * Get the contents of an {@code DSSDocument} as a {@code byte[]}.
	 *
	 * @param document
	 * @return
	 */
	public static byte[] toByteArray(final DSSDocument document) {
		try (InputStream is = document.openStream()) {
			return toByteArray(is);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Get the contents of an {@code InputStream} as a {@code byte[]}.
	 *
	 * @param inputStream
	 * @return
	 */
	public static byte[] toByteArray(final InputStream inputStream) {
		if (inputStream == null) {
			throw new NullPointerException();
		}
		try {
			final byte[] bytes = Utils.toByteArray(inputStream);
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method saves the given array of {@code byte} to the provided {@code File}.
	 *
	 * @param bytes
	 *            to save
	 * @param file
	 * @throws DSSException
	 */
	public static void saveToFile(final byte[] bytes, final File file) throws DSSException {
		file.getParentFile().mkdirs();
		try (InputStream is = new ByteArrayInputStream(bytes); OutputStream os = new FileOutputStream(file)) {
			Utils.copy(is, os);
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
	public static String getDeterministicId(final Date signingTime, TokenIdentifier id) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos);) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			if (id != null) {
				dos.writeChars(id.asXmlId());
			}
			dos.close();
			final String deterministicId = "id-" + getMD5Digest(baos.toByteArray());
			return deterministicId;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns a Hex encoded of the MD5 digest of ByteArrayOutputStream
	 *
	 * @param bytes
	 * @return
	 */
	public static String getMD5Digest(byte[] bytes) {
		try {
			byte[] digestValue = digest(DigestAlgorithm.MD5, bytes);
			return Utils.toHex(digestValue);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public static long toLong(final byte[] bytes) {
		// Long.valueOf(new String(bytes)).longValue();
		ByteBuffer buffer = ByteBuffer.allocate(8);
		buffer.put(bytes, 0, Long.SIZE / 8);
		// TODO: (Bob: 2014 Jan 22) To be checked if it is not platform dependent?
		buffer.flip();// need flip
		return buffer.getLong();
	}

	/**
	 * This method returns the {@code X500Principal} corresponding to the given string or {@code null} if the conversion
	 * is not possible.
	 *
	 * @param x500PrincipalString
	 *            a {@code String} representation of the {@code X500Principal}
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
	 * This method compares two {@code X500Principal}s. {@code X500Principal.CANONICAL} and
	 * {@code X500Principal.RFC2253} forms are compared.
	 * TODO: (Bob: 2014 Feb 20) To be investigated why the standard equals does not work!?
	 *
	 * @param firstX500Principal
	 * @param secondX500Principal
	 * @return
	 */
	public static boolean x500PrincipalAreEquals(final X500Principal firstX500Principal, final X500Principal secondX500Principal) {
		if ((firstX500Principal == null) || (secondX500Principal == null)) {
			return false;
		}
		if (firstX500Principal.equals(secondX500Principal)) {
			return true;
		}
		final Map<String, String> firstStringStringHashMap = DSSASN1Utils.get(firstX500Principal);
		final Map<String, String> secondStringStringHashMap = DSSASN1Utils.get(secondX500Principal);
		final boolean containsAll = firstStringStringHashMap.entrySet().containsAll(secondStringStringHashMap.entrySet());

		return containsAll;
	}

	/**
	 * @param x500Principal
	 *            to be normalized
	 * @return {@code X500Principal} normalized
	 */
	public static X500Principal getNormalizedX500Principal(final X500Principal x500Principal) {
		final String utf8Name = DSSASN1Utils.getUtf8String(x500Principal);
		final X500Principal x500PrincipalNormalized = new X500Principal(utf8Name);
		return x500PrincipalNormalized;
	}

	/**
	 * This method returns an UTC date base on the year, the month and the day. The year must be encoded as 1978... and
	 * not 78
	 *
	 * @param year
	 *            the value used to set the YEAR calendar field.
	 * @param month
	 *            the month. Month value is 0-based. e.g., 0 for January.
	 * @param day
	 *            the value used to set the DAY_OF_MONTH calendar field.
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
	 * @param date
	 *            {@code Date} to change
	 * @param days
	 *            number of days (can be negative)
	 * @return new {@code Date}
	 */
	public static Date getDate(final Date date, int days) {

		final Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		calendar.add(Calendar.DATE, days);
		final Date newDate = calendar.getTime();
		return newDate;
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

	/**
	 * This method lists all defined security providers.
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

	/**
	 * Reads maximum {@code headerLength} bytes from {@code dssDocument} to the given {@code byte} array.
	 *
	 * @param dssDocument
	 *            {@code DSSDocument} to read
	 * @param headerLength
	 *            {@code int}: maximum number of bytes to read
	 * @param destinationByteArray
	 *            destination {@code byte} array
	 * @return
	 */
	public static int readToArray(final DSSDocument dssDocument, final int headerLength, final byte[] destinationByteArray) {
		try (InputStream inputStream = dssDocument.openStream()) {
			int read = inputStream.read(destinationByteArray, 0, headerLength);
			return read;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Reads the first byte from the DSSDocument
	 * 
	 * @param dssDocument
	 *            the document
	 * @return the first byte
	 * @throws DSSException
	 */
	public static byte readFirstByte(final DSSDocument dssDocument) throws DSSException {
		byte[] result = new byte[1];
		try (InputStream inputStream = dssDocument.openStream()) {
			inputStream.read(result, 0, 1);
		} catch (IOException e) {
			throw new DSSException(e);
		}
		return result[0];
	}

	/**
	 * Concatenates all the arrays into a new array. The new array contains all of the element of each array followed by
	 * all of the elements of the next array. When an array is
	 * returned, it is always a new array.
	 *
	 * @param arrays
	 *            {@code byte} arrays to concatenate
	 * @return the new {@code byte} array
	 */
	public static byte[] concatenate(byte[]... arrays) {
		if ((arrays == null) || (arrays.length == 0) || ((arrays.length == 1) && (arrays[0] == null))) {
			return null;
		}
		if (arrays.length == 1) {
			return arrays[0].clone();
		}
		int joinedLength = 0;
		for (final byte[] array : arrays) {
			if (array != null) {
				joinedLength += array.length;
			}
		}
		byte[] joinedArray = new byte[joinedLength];
		int destinationIndex = 0;
		for (final byte[] array : arrays) {
			if (array != null) {

				System.arraycopy(array, 0, joinedArray, destinationIndex, array.length);
				destinationIndex += array.length;
			}
		}
		return joinedArray;
	}

	public static String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level, ASiCContainerType containerType) {
		StringBuilder finalName = new StringBuilder();

		String originalName = null;
		if (containerType != null) {
			originalName = "container";
		} else {
			originalName = originalFile.getName();
		}

		if (Utils.isStringNotEmpty(originalName)) {
			int dotPosition = originalName.lastIndexOf('.');
			if (dotPosition > 0) {
				// remove extension
				finalName.append(originalName.substring(0, dotPosition));
			} else {
				finalName.append(originalName);
			}
		} else {
			finalName.append("document");
		}

		if (SigningOperation.SIGN.equals(operation)) {
			finalName.append("-signed-");
		} else if (SigningOperation.EXTEND.equals(operation)) {
			finalName.append("-extended-");
		}

		finalName.append(Utils.lowerCase(level.name().replaceAll("_", "-")));
		finalName.append('.');

		if (containerType != null) {
			switch (containerType) {
			case ASiC_S:
				finalName.append("asics");
				break;
			case ASiC_E:
				finalName.append("asice");
				break;
			default:
				break;
			}
		} else {
			SignatureForm signatureForm = level.getSignatureForm();
			switch (signatureForm) {
			case XAdES:
				finalName.append("xml");
				break;
			case CAdES:
				finalName.append("pkcs7");
				break;
			case PAdES:
				finalName.append("pdf");
				break;
			default:
				break;
			}
		}

		return finalName.toString();
	}

	public static String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level) {
		return getFinalFileName(originalFile, operation, level, null);
	}

	public static String decodeUrl(String uri) {
		try {
			return URLDecoder.decode(uri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.error("Unable to decode '" + uri + "' : " + e.getMessage(), e);
		}
		return uri;
	}

}