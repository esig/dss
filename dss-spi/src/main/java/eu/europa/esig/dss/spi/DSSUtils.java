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
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.X520Attributes;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;

/**
 * Set of common utils
 */
public final class DSSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSUtils.class);

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	/** Empty byte array */
	public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

	/** Represents a carriage return '\r' character */
	public static final byte CARRIAGE_RETURN = '\r';

	/** Represents a new line '\n' character */
	public static final byte LINE_FEED = '\n';

	/** RFC 3339 DateTime format used by default */
	public static final String RFC3339_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/** The UTC timezone (GMT+0), used by default */
	public static final TimeZone UTC_TIMEZONE = TimeZone.getTimeZone("UTC");

	/** The UTF-8 encoding name string */
	public static final String UTF8_ENCODING = "UTF-8";

	/** This array contains character bytes, representing a line break (new line, carriage return) */
	private static final byte[] LINE_BREAK_CHARS = { CARRIAGE_RETURN, LINE_FEED };

	/** The URN OID prefix (RFC 3061) */
	public static final String OID_NAMESPACE_PREFIX = "urn:oid:";

	/**
	 * This class is a utility class and cannot be instantiated.
	 */
	private DSSUtils() {
		// empty
	}

	/**
	 * Formats a date to use according to RFC 3339. The date is aligned to UTC TimeZone
	 * Example: "2019-11-19T17:28:15Z"
	 *
	 * @param date
	 *            the date to be converted
	 * @return the textual representation (a null date will result in "N/A")
	 */
	public static String formatDateToRFC(final Date date) {
		return formatDateWithCustomFormat(date, RFC3339_TIME_FORMAT);
	}

	/**
	 * Parses a {@code String} date to {@code Date}
	 *
	 * @param str {@link String} in RFC format, e.g. "2019-11-19T17:28:15Z"
	 * @return {@link Date}
	 */
	public static Date parseRFCDate(final String str) {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat(RFC3339_TIME_FORMAT);
			sdf.setTimeZone(UTC_TIMEZONE);
			sdf.setLenient(false);
			return sdf.parse(str);
		} catch (Exception e) {
			throw new IllegalArgumentException(String.format("String '%s' doesn't follow the pattern '%s'", str, RFC3339_TIME_FORMAT));
		}
	}

	/**
	 * Formats the date according to the given format (with system TimeZone)
	 * 
	 * @param date {@link Date} to transform to a String
	 * @param format {@link String} representing a Date format to be used
	 * @return {@link String} formatted date
	 */
	public static String formatDateWithCustomFormat(final Date date, final String format) {
		return formatDateWithCustomFormat(date, format, UTC_TIMEZONE);
	}
	
	/**
	 * Formats the date according to the given format and timeZone as {@code String}.
	 * <p>
	 * NOTE : When null or empty string is provided, the system default timezone is used!
	 * 
	 * @param date {@link Date} to transform to a String
	 * @param format {@link String} representing a Date format to be used
	 * @param timeZone {@link String} specifying a TimeZone
	 * @return {@link String} formatted date
	 */
	public static String formatDateWithCustomFormat(final Date date, final String format, final String timeZone) {
		return formatDateWithCustomFormat(date, format, Utils.isStringNotEmpty(timeZone) ? TimeZone.getTimeZone(timeZone) : null);
	}

	/**
	 * Formats the date according to the given format and {@code TimeZone}
	 *
	 * NOTE : When null TimeZone is provided, the system default timezone is used!
	 *
	 * @param date {@link Date} to transform to a String
	 * @param format {@link String} representing a Date format to be used
	 * @param timeZone {@link TimeZone} specifying a TimeZone
	 * @return {@link String} formatted date
	 */
	public static String formatDateWithCustomFormat(final Date date, final String format, final TimeZone timeZone) {
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat(format);
		if (timeZone != null) {
			simpleDateFormat.setTimeZone(timeZone);
		}
		return (date == null) ? "N/A" : simpleDateFormat.format(date);
	}

	/**
	 * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
	 * String will be double the length of the passed array, as it takes two characters to represent any given byte. If
	 * the input array is null then null is returned. The obtained string is converted to uppercase.
	 *
	 * @param value
	 *            the value to be converted to hexadecimal
	 * @return the hexadecimal String
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
	 */
	public static String convertToPEM(final CertificateToken cert) {
		return convertToPEM(cert.getCertificate());
	}

	private static String convertToPEM(Object obj) {
		try (StringWriter out = new StringWriter(); PemWriter pemWriter = new PemWriter(out)) {
			pemWriter.writeObject(new JcaMiscPEMGenerator(obj));
			pemWriter.flush();
			return out.toString();
		} catch (Exception e) {
			throw new DSSException("Unable to convert DER to PEM", e);
		}
	}

	/**
	 * This method returns true if the inputStream starts with an ASN.1 Sequence
	 * 
	 * @param is
	 *            the inputstream to be tested
	 * @return true if DER encoded
	 */
	public static boolean isStartWithASN1SequenceTag(InputStream is) {
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
	 * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied
	 * in binary or printable (PEM / Base64) encoding.
	 * <p>
	 * If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 * {@code -----BEGIN CERTIFICATE-----}, and must be bounded at the end by {@code -----END CERTIFICATE-----}.
	 * 
	 * @param file
	 *            the file with the certificate
	 * @return the certificate token
	 */
	public static CertificateToken loadCertificate(final File file) {
		try {
			final InputStream inputStream = Files.newInputStream(file.toPath());
			return loadCertificate(inputStream);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to find a file '%s' : %s", file.getAbsolutePath(), e.getMessage()), e);
		}
	}

	/**
	 * This method loads a certificate from the given location. The certificate must be DER-encoded and may be supplied
	 * in binary or printable (PEM / Base64) encoding.
	 * <p>
	 * If the certificate is provided in Base64 encoding, it must be bounded at the beginning by
	 * {@code -----BEGIN CERTIFICATE-----}, and must be bounded at the end by {@code -----END CERTIFICATE-----}.
	 * 
	 * @param inputStream
	 *            input stream containing the certificate
	 * @return the certificate token
	 */
	public static CertificateToken loadCertificate(final InputStream inputStream) {
		List<CertificateToken> certificates = loadCertificates(inputStream);
		if (certificates.size() == 1) {
			return certificates.get(0);
		}
		throw new DSSException("Could not parse certificate");
	}

	/**
	 * Loads a collection of certificates from a p7c source
	 *
	 * @param inputStream {@link InputStream} p7c
	 * @return a list of {@link CertificateToken}s
	 */
	public static List<CertificateToken> loadCertificateFromP7c(InputStream inputStream) {
		return loadCertificates(inputStream);
	}

	private static List<CertificateToken> loadCertificates(InputStream inputStream) {
		final List<CertificateToken> certificates = new ArrayList<>();
		try (InputStream is = inputStream) {
			@SuppressWarnings("unchecked")
			final Collection<X509Certificate> certificatesCollection = (Collection<X509Certificate>) CertificateFactory
					.getInstance("X.509", DSSSecurityProvider.getSecurityProviderName()).generateCertificates(is);
			if (certificatesCollection != null) {
				for (X509Certificate cert : certificatesCollection) {
					certificates.add(new CertificateToken(cert));
				}
			}
			if (certificates.isEmpty()) {
				throw new DSSException("No certificate found in the InputStream");
			}
			return certificates;
		} catch (DSSException e) {
		  	throw e;
		} catch (Exception e) {
			throw new DSSException("Unable to load certificate(s) : " + e.getMessage(), e);
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
	 * @return the certificate token
	 */
	public static CertificateToken loadCertificate(final byte[] input) {
		Objects.requireNonNull(input, "Input binary cannot be null");
		final InputStream inputStream = new ByteArrayInputStream(input); // closed inside
		return loadCertificate(inputStream);
	}

	/**
	 * This method loads a certificate from a base 64 encoded String
	 *
	 * @param base64Encoded
	 *            the base64 encoded certificate
	 * @return the certificate token
	 */
	public static CertificateToken loadCertificateFromBase64EncodedString(final String base64Encoded) {
		final byte[] bytes = Utils.fromBase64(base64Encoded);
		return loadCertificate(bytes);
	}

	/**
	 * This method digests the given string with SHA1 algorithm and encode returned array of bytes as hex string.
	 *
	 * @param stringToDigest
	 *            Everything in the name
	 * @return hex encoded digest value
	 */
	public static String getSHA1Digest(final String stringToDigest) {
		return Utils.toHex(digest(DigestAlgorithm.SHA1, stringToDigest.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * This method checks if the provided {@code str} represents a SHA-1 digest
	 *
	 * @param str {@link String} to check
	 * @return TRUE if the string represents SHA-1 digest, FALSE otherwise
	 */
	public static boolean isSHA1Digest(final String str) {
		return Utils.isStringNotBlank(str) && Utils.isHexEncoded(str) && str.length() == 40;
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
	public static byte[] digest(final DigestAlgorithm digestAlgorithm, final byte[] data) {
		Objects.requireNonNull(data, "The data cannot be null");
		switch (digestAlgorithm) {
		case SHAKE128:
			return computeDigest(new SHAKEDigest(128), data);
		case SHAKE256:
			return computeDigest(new SHAKEDigest(256), data);
		default:
			final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
			return messageDigest.digest(data);
		}
	}

	private static byte[] computeDigest(org.bouncycastle.crypto.Digest digest, byte[] data) {
		try (DigestOutputStream dos = new DigestOutputStream(digest)) {
			dos.write(data);
			return dos.getDigest();
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute digest : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets the message digest from the {@code DigestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @return {@link MessageDigest}
	 */
	public static MessageDigest getMessageDigest(DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "The DigestAlgorithm cannot be null");
		try {
			return digestAlgorithm.getMessageDigest();
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException(String.format("Unable to create a MessageDigest for algorithm '%s'", digestAlgorithm), e);
		}
	}

	/**
	 * Creates a {@code DigestDocument} with the provided {@code Digest}
	 *
	 * @param digest {@link Digest} to use to create a {@link DigestDocument}
	 * @return {@link DigestDocument} containing {@link Digest}
	 */
	public static DigestDocument toDigestDocument(Digest digest) {
		return toDigestDocument(digest.getAlgorithm(), digest.getValue());
	}

	/**
	 * Creates a {@code DigestDocument} with the provided {@code DigestAlgorithm} and {@code digestValue}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param digestValue byte array containing digest value
	 * @return {@link DigestDocument} containing the given digest value with the defined algorithm
	 */
	public static DigestDocument toDigestDocument(DigestAlgorithm digestAlgorithm, byte[] digestValue) {
		return new DigestDocument(digestAlgorithm, Utils.toBase64(digestValue));
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
	public static byte[] digest(final DigestAlgorithm digestAlgo, final InputStream inputStream) {
		try {
			final MessageDigest messageDigest = getMessageDigest(digestAlgo);
			final byte[] buffer = new byte[4096];
			int count = 0;
			while ((count = inputStream.read(buffer)) > 0) {
				messageDigest.update(buffer, 0, count);
			}
			return messageDigest.digest();
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute digest : %s", e.getMessage()), e);
		}
	}

	/**
	 * Computes the digests for the {@code document}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 * @param document {@link DSSDocument} to calculate the digest on
	 * @return digest value
	 */
	public static byte[] digest(DigestAlgorithm digestAlgorithm, DSSDocument document) {
		return document.getDigestValue(digestAlgorithm);
	}

	/**
	 * Computes the digest on the data concatenation
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 * @param data a sequence of byte arrays to compute digest on
	 * @return digest value
	 */
	public static byte[] digest(DigestAlgorithm digestAlgorithm, byte[]... data) {
		final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
		for (final byte[] bytes : data) {
			messageDigest.update(bytes);
		}
		return messageDigest.digest();
	}

	/**
	 * FROM: Apache
	 * Reads the contents of a file into a byte array.
	 * The file is always closed.
	 *
	 * @param file
	 *            the file to read, must not be {@code null}
	 * @return the file contents, never {@code null}
	 */
	public static byte[] toByteArray(final File file) {
		Objects.requireNonNull(file, "The file cannot be null");
		try (InputStream is = openInputStream(file)) {
			return toByteArray(is);
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to read content of file '%s'. Reason : %s",
					file, e.getMessage()), e);
		}
	}

	/**
	 * FROM: Apache Opens a {@link java.io.FileInputStream} for the specified file,
	 * providing better error messages than simply calling
	 * {@code new FileInputStream(file)}. At the end of the method either the stream
	 * will be successfully opened, or an exception will have been thrown. An
	 * exception is thrown if the file does not exist. An exception is thrown if the
	 * file object exists but is a directory. An exception is thrown if the file
	 * exists but cannot be read.
	 *
	 * @param file
	 *             the file to open for input, must not be {@code null}
	 * @return a new {@link java.io.InputStream} for the specified file
	 * @throws NullPointerException
	 *                              if the file is null
	 * @throws IOException
	 *                              if the file cannot be read
	 */
	private static InputStream openInputStream(final File file) throws IOException {
		Objects.requireNonNull(file, "The file cannot be null");
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
		return Files.newInputStream(file.toPath());
	}

	/**
	 * Get the contents of an {@code DSSDocument} as a {@code byte[]}.
	 *
	 * @param document
	 *            the document to read
	 * @return the content as byte array
	 */
	public static byte[] toByteArray(final DSSDocument document) {
		try (InputStream is = document.openStream()) {
			return toByteArray(is);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to read content of document with name '%s'. Reason : %s",
					document.getName(), e.getMessage()), e);
		}
	}

	/**
	 * Get the contents of an {@code InputStream} as a {@code byte[]}.
	 *
	 * @param inputStream
	 *            the inputstream to read
	 * @return the content of the inputstream as byte array
	 */
	public static byte[] toByteArray(final InputStream inputStream) {
		Objects.requireNonNull(inputStream, "The InputStream cannot be null");
		try {
			return Utils.toByteArray(inputStream);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to read InputStream : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets CMSSignedData from the {@code InputStream}
	 *
	 * @param inputStream {@link InputStream} contained CMSSignedData
	 * @return {@link CMSSignedData}
	 */
	public static CMSSignedData toCMSSignedData(final InputStream inputStream) {
		try (InputStream is = inputStream) {
			return new CMSSignedData(is);
		} catch (IOException | CMSException e) {
			throw new DSSException("Not a valid CAdES file", e);
		}
	}
	
	/**
	 * Gets CMSSignedData from the {@code document} bytes
	 * 
	 * @param document {@link DSSDocument} contained CMSSignedData
	 * @return {@link CMSSignedData}
	 */
	public static CMSSignedData toCMSSignedData(final DSSDocument document) {
		return toCMSSignedData(document.openStream());
	}

	/**
	 * Creates {@code CMSSignedData} from the DER-encoded binaries representing CMS
	 *
	 * @param encoded byte array representing CMSSignedData
	 * @return {@link CMSSignedData}
	 */
	public static CMSSignedData toCMSSignedData(final byte[] encoded) {
		try {
			return new CMSSignedData(encoded);
		} catch (CMSException e) {
			throw new DSSException("Not a valid CMS", e);
		}
	}

	/**
	 * This method verifies if the document is empty (does not have body)
	 *
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document is empty, FALSE otherwise
	 */
	public static boolean isEmpty(DSSDocument document) {
		if (document instanceof DigestDocument) {
			return true;
		}
		try (InputStream is = document.openStream()) {
			return is.read() == -1;
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to check if document has a content: %s", e.getMessage()), e);
		}
	}
	
	/**
	 * Checks if the document contains a TimeStampToken
	 * 
	 * @param document
	 *                 the {@link DSSDocument} to be checked
	 * @return true if the document is a timestamp
	 */
	public static boolean isTimestampToken(final DSSDocument document) {
		try (InputStream is = document.openStream()) {
			CMSSignedDataParser cmsSignedDataParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), is);
			return PKCSObjectIdentifiers.id_ct_TSTInfo.getId().equals(cmsSignedDataParser.getSignedContentTypeOID());
		} catch (Exception e) {
			// skip exception
			return false;
		}
	}

	/**		
	 * Returns byte size of the given document
	 * @param dssDocument {@link DSSDocument} to get size for
	 * @return long size of the given document
	 */
	public static long getFileByteSize(DSSDocument dssDocument) {
		try (InputStream is = dssDocument.openStream()) {
			return Utils.getInputStreamSize(is);
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read the document with name [%s]", dssDocument.getName()), e);
		}
	}

	/**
	 * This method saves the given array of {@code byte} to the provided {@code File}.
	 *
	 * @param bytes
	 *            the binary to save
	 * @param file
	 *            the file where to store
	 */
	public static void saveToFile(final byte[] bytes, final File file) {
		file.getParentFile().mkdirs();
		try (InputStream is = new ByteArrayInputStream(bytes); OutputStream os = Files.newOutputStream(file.toPath())) {
			Utils.copy(is, os);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to save a file : %s", e.getMessage()), e);
		}
	}

	/**
	 * This method replaces all special characters by an underscore
	 * 
	 * @param str
	 *            the string / filename / url to normalize
	 * @return the normalized {@link String}
	 */
	public static String getNormalizedString(final String str) {
		if (str == null) {
			return null;
		}
		String normalizedStr = decodeURI(str);
		normalizedStr = normalizedStr.replaceAll("\\W", "_");
		return normalizedStr;
	}

	/**
	 * Return a unique id for a date and the certificateToken id.
	 *
	 * @param signingTime
	 *            the signing time
	 * @param id
	 *            the token identifier
	 * @return a unique string
	 */
	public static String getDeterministicId(final Date signingTime, TokenIdentifier id) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			if (id != null) {
				dos.writeChars(id.asXmlId());
			}
			dos.flush();
			return "id-" + getMD5Digest(baos.toByteArray());
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute a deterministic Id : %s", e.getMessage()), e);
		}
	}

	/**
	 * Return a unique id for a counter signature.
	 *
	 * @param signingTime
	 *            the signing time
	 * @param id
	 *            the token identifier
	 * @param masterSignatureId
	 *            id of a signature to be counter-signed
	 * @return a unique string
	 */
	public static String getCounterSignatureDeterministicId(final Date signingTime, TokenIdentifier id, String masterSignatureId) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (signingTime != null) {
				dos.writeLong(signingTime.getTime());
			}
			if (id != null) {
				dos.writeChars(id.asXmlId());
			}
			if (masterSignatureId != null) {
				dos.writeChars(masterSignatureId);
			}
			dos.flush();
			return "id-" + getMD5Digest(baos.toByteArray());
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute a deterministic Id for a counter-signature : %s", e.getMessage()), e);
		}
	}

	/**
	 * Returns a Hex encoded of the MD5 digest of binaries
	 *
	 * @param bytes
	 *            the bytes to be digested
	 * @return the hex encoded MD5 digest
	 */
	public static String getMD5Digest(byte[] bytes) {
		return Utils.toHex(digest(DigestAlgorithm.MD5, bytes));
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
			return new X500Principal(x500PrincipalString, X520Attributes.getUppercaseDescriptionForOids());
		} catch (Exception e) {
			LOG.warn("Unable to create an instance of X500Principal : {}", e.getMessage());
			return null;
		} 
	}

	/**
	 * This method returns an UTC date base on the year, the month and the day. 
	 * The year must be encoded as 1978... and not 78
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
		calendar.set(Calendar.MILLISECOND, 0);
		return calendar.getTime();
	}

	/**
	 * This method lists all defined security providers.
	 */
	public static void printSecurityProviders() {
		final Provider[] providers = Security.getProviders();
		for (final Provider provider : providers) {
			LOG.info("PROVIDER: {}", provider.getName());
			final Set<Provider.Service> services = provider.getServices();
			for (final Provider.Service service : services) {
				LOG.info("\tALGORITHM: {} / {} / {}", service.getAlgorithm(), service.getType(),
						service.getClassName());
			}
		}
	}

	/**
	 * Reads the first byte from the DSSDocument
	 * 
	 * @param dssDocument
	 *            the document
	 * @return the first byte
	 */
	public static byte readFirstByte(final DSSDocument dssDocument) {
		byte[] result = new byte[1];
		try (InputStream inputStream = dssDocument.openStream()) {
			inputStream.read(result, 0, 1);
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read first byte of the document. Reason : %s", e.getMessage()), e);
		}
		return result[0];
	}

	/**
	 * This method decodes a URI to be compliant with the RFC 3986 (see DSS-2411 for details)
	 *
	 * @param uri {@link String}
	 * @return {@link String} UTF-8
	 */
	public static String decodeURI(String uri) {
		if (uri == null) {
			return null;
		}
		try {
			uri = uri.replace("+", "%2B"); // preserve '+' characters
			return URLDecoder.decode(uri, UTF8_ENCODING);
		} catch (UnsupportedEncodingException | IllegalArgumentException e) {
			LOG.warn("Unable to decode '{}' : {}", uri, e.getMessage(), e);
		}
		return uri;
	}
	
	/**
	 * This method encodes a URI to be compliant with the RFC 3986 (see DSS-1475 for details)
	 *
	 * @param fileURI the uri to be encoded
	 * @return the encoded result
	 */
	public static String encodeURI(String fileURI) {
		StringBuilder sb = new StringBuilder();
		String uriDelimiter = "";
		final String[] uriParts = fileURI.split("/");
		for (String part : uriParts) {
			sb.append(uriDelimiter);
			sb.append(encodePartURI(part));
			uriDelimiter = "/";
		}
		return sb.toString();
	}
	
	/**
	 * This method encodes a partial URI to be compliant with the RFC 3986 (see DSS-1475 for details)
	 * @param uriPart the partial uri to be encoded
	 * @return the encoded result
	 */
	private static String encodePartURI(String uriPart) {
		try {
			return URLEncoder.encode(uriPart, UTF8_ENCODING).replace("+", "%20");
		} catch (Exception e) {
			LOG.warn("Unable to encode uri '{}' : {}", uriPart, e.getMessage());
			return uriPart;
		}
	}
	
	/**
	 * Returns a message retrieved from an exception,
	 * its cause message if the first is not defined,
	 * or exception class name if non of them is specified
	 * 
	 * @param e {@link Exception} to get message for
	 * @return {@link String} exception message
	 */
	public static String getExceptionMessage(Exception e) {
		if (e == null) {
			throw new DSSException("Cannot retrieve a message. The exception is null!");
		}
		
		if (e.getMessage() != null) {
			return e.getMessage();
			
		} else if (e.getCause() != null && e.getCause().getMessage() != null) {
			return e.getCause().getMessage();
			
		} else {
			return e.getClass().getName();
			
		}
	}

	/**
	 * Returns {@code Digest} of the {@code dssDocument}
	 *
	 * @param digestAlgo {@link DigestAlgorithm} to use
	 * @param dssDocument {@link DSSDocument} to compute digest on
	 * @return {@link Digest}
	 */
	public static Digest getDigest(DigestAlgorithm digestAlgo, DSSDocument dssDocument) {
		return new Digest(digestAlgo, digest(digestAlgo, dssDocument));
	}
	
	/**
	 * Replaces null ASCII characters 00-31 and 127 with ''
	 * 
	 * @param str {@link String} to remove Ctrls characters from
	 * @return {@link String} without Ctrls characters
	 */
	public static String removeControlCharacters(String str) {
		if (str != null) {
			String cleanedString = str.replaceAll("[^\\P{Cntrl}]+", "");
			if (!str.equals(cleanedString)) {
				LOG.warn("The string [{}] contains illegal characters and was replaced to [{}]", str, cleanedString);
			}
			return cleanedString;
		}
		return null;
	}

	/**
	 * Replaces all non-alphanumeric characters in the {@code str} by the {@code replacement}
	 *
	 * @param str {@link String} to replace non-alphanumeric characters in
	 * @param replacement {@link String} to be used as a replacement
	 * @return {@link String}
	 */
	public static String replaceAllNonAlphanumericCharacters(String str, String replacement) {
		if (str != null) {
			return str.replaceAll("[^\\p{L}\\p{Nd}]+", replacement);
		}
		return null;
	}

	/**
	 * Replaces all invalid XML characters in the {@code str} by the {@code replacement}
	 *
	 * @param str {@link String} to replace invalid XML characters in
	 * @param replacement {@link String} to be used as a replacement
	 * @return {@link String}
	 */
	public static String replaceInvalidXmlCharacters(String str, String replacement) {
		if (str != null) {
			return str.replaceAll("[^\\u0009\\u000A\\u000D\\u0020-\\uD7FF\\uE000-\\uFFFD\\x{10000}-\\x{10FFFF}]", replacement);
		}
		return null;
	}

	/**
	 * Checks if the given id is a URN representation of OID according to IETF RFC 3061
	 * 
	 * @param id {@link String} to check
	 * @return TRUE if the provided id is a URN representation of OID, FALSE otherwise
	 */
	public static boolean isUrnOid(String id) {
		return id != null && id.matches("^(?i)urn:oid:.*$");
	}

	/**
	 * Checks if the given {@code oid} is a valid OID
	 * Ex.: 1.3.6.1.4.1.343 = valid
	 *      25.25 = invalid
	 *      http://sample.com = invalid
	 * Source: regexr.com/38m0v (OID Validator)
	 * 
	 * @param oid {@link String} oid to verify
	 * @return TRUE if the string is a valid OID code, FALSE otherwise
	 */
	public static boolean isOidCode(String oid) {
		return oid != null && oid.matches("^([0-2])((\\.0)|(\\.[1-9][0-9]*))*$");
	}
	
	/**
	 * Keeps only code of the oid string
	 * e.g. "urn:oid:1.2.3" to "1.2.3"
	 * 
	 * @param urnOid {@link String} uri to extract OID value from
	 * @return OID Code
	 */
	public static String getOidCode(String urnOid) {
		if (urnOid == null) {
			return null;
		}
		return urnOid.substring(urnOid.lastIndexOf(':') + 1);
	}

	/**
	 * Returns a URN URI generated from the given OID:
	 * <p>
	 * Ex.: OID = 1.2.4.5.6.8 becomes URI = urn:oid:1.2.4.5.6.8
	 * <p>
	 * Note: see RFC 3061 "A URN Namespace of Object Identifiers"
	 *
	 * @param oid {@link String} to be converted to URN URI
	 * @return URI based on the algorithm's OID
	 */
	public static String toUrnOid(String oid) {
		return OID_NAMESPACE_PREFIX + oid;
	}
	
	/**
	 * Normalizes and retrieves a {@code String} identifier (to be used for non-XAdES processing).
	 * Examples:
	 *      "http://website.com" = "http://website.com"
	 *      "urn:oid:1.2.3" = "1.2.3"
	 *      "1.2.3" = "1.2.3"
	 * 
	 * @param oidOrUriString {@link String} identifier
	 * @return {@link String}
	 */
	public static String getObjectIdentifierValue(String oidOrUriString) {
		return getObjectIdentifierValue(oidOrUriString, null, false);
	}

	/**
	 * This method returns a URI value of the {@code oidOrUriString} taking into account
	 * the defined {@code ObjectIdentifierQualifier} (to be used for XAdES processing).
	 * Examples:
	 *     "http://nowina.lu/policy" = "http://nowina.lu/policy"
	 *     "1.2.3.4.5" = "1.2.3.4.5"
	 *     "urn:oid:1.2.3.4.5" = "1.2.3.4.5"
	 *
	 * @param oidOrUriString {@link String} identifier value
	 * @param qualifier {@link ObjectIdentifierQualifier} when present
	 * @return {@link String} URI
	 */
	public static String getObjectIdentifierValue(String oidOrUriString, ObjectIdentifierQualifier qualifier) {
		return getObjectIdentifierValue(oidOrUriString, qualifier, true);
	}

	private static String getObjectIdentifierValue(String oidOrUriString, ObjectIdentifierQualifier qualifier, boolean xades) {
		String value = oidOrUriString;
		if (Utils.isStringNotEmpty(oidOrUriString)) {
			value = trimWhitespacesAndNewlines(value);
			if (DSSUtils.isUrnOid(value)) {
				if (xades && !ObjectIdentifierQualifier.OID_AS_URN.equals(qualifier)) {
					LOG.debug("When OID is encoded as URN, a Qualifier=\"OIDAsURN\" shall be used!");
				}
				value = DSSUtils.getOidCode(value);

			} else if (DSSUtils.isOidCode(value)) {
				if (xades && ObjectIdentifierQualifier.OID_AS_URN.equals(qualifier)) {
					LOG.debug("When OID is encoded as URI, a Qualifier=\"OIDAsURN\" shall not be used!");
				}

			} else {
				// OIDAsURN or OIDAsURI
				if (xades && qualifier != null) {
					LOG.debug("When URI is used, a Qualifier attribute shall not be present!");
				}
			}
		}
		return value;
	}

	/**
	 * Trims whitespaces and new line characters
	 *
	 * @param str {@link String} to trim
	 * @return {@link String}
	 */
	public static String trimWhitespacesAndNewlines(String str) {
		if (str != null) {
			str = str.replace("\n", "");
			str = str.replace("\r", "");
			str = Utils.trim(str);
		}
		return str;
	}
	
	/**
	 * Trims the leading string if it is a leading part of the text
	 * 
	 * @param text {@link String} to trim
	 * @param leading {@link String} to remove
	 * @return trimmed text {@link String}
	 */
	public static String stripFirstLeadingOccurrence(String text, String leading) {
		if (text == null) {
			return null;
		}
		if (leading == null) {
			return text;
		}
		return text.replaceFirst("^"+leading, "");
	}

	/**
	 * Returns a list of document names from the given document list
	 * 
	 * @param dssDocuments a list of {@link DSSDocument}s to get names of
	 * @return a list of {@link String} document names
	 */
	public static List<String> getDocumentNames(List<DSSDocument> dssDocuments) {
		if (Utils.isCollectionNotEmpty(dssDocuments)) {
			return dssDocuments.stream().map(DSSDocument::getName).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	/**
	 * Returns a document with the given {@code fileName} from the list of {@code documents}, when present
	 *
	 * @param documents a list of {@link DSSDocument}s
	 * @param fileName {@link String} name of the document to extract
	 * @return {@link DSSDocument} when found, NULL otherwise
	 */
	public static DSSDocument getDocumentWithName(List<DSSDocument> documents, String fileName) {
		for (DSSDocument document : documents) {
			if (fileName.equals(document.getName())) {
				return document;
			}
		}
		return null;
	}

	/**
	 * Returns the last document in the alphabetical ascendant order
	 *
	 * @param documents a list of {@link DSSDocument}s
	 * @return {@link DSSDocument}
	 */
	public static DSSDocument getDocumentWithLastName(List<DSSDocument> documents) {
		if (Utils.isCollectionNotEmpty(documents)) {
			List<String> documentNames = DSSUtils.getDocumentNames(documents);
			Collections.sort(documentNames);
			return DSSUtils.getDocumentWithName(documents, documentNames.get(documentNames.size() - 1));
		}
		return null;
	}

	/**
	 * Adds all objects from {@code toAddCollection} into {@code currentCollection} without duplicates
	 *
	 * @param currentCollection a collection to enrich
	 * @param toAddCollection a collection to add values from
	 * @param <T> an Object
	 */
	public static <T> void enrichCollection(Collection<T> currentCollection, Collection<T> toAddCollection) {
		for (T object : toAddCollection) {
			if (!currentCollection.contains(object)) {
				currentCollection.add(object);
			}
		}
	}

	/**
	 * This method ensures the {@code SignatureValue} has an expected format and converts it when required
	 *
	 * @param expectedAlgorithm {@link SignatureAlgorithm} the target SignatureAlgorithm
	 * @param signatureValue {@link SignatureValue} the obtained SignatureValue
	 * @return {@link SignatureValue} with the target {@link SignatureAlgorithm}
	 */
	public static SignatureValue convertECSignatureValue(SignatureAlgorithm expectedAlgorithm,
														 SignatureValue signatureValue)   {
		SignatureValue newSignatureValue = new SignatureValue();
		newSignatureValue.setAlgorithm(expectedAlgorithm);

		byte[] signatureValueBinaries;
		final EncryptionAlgorithm expectedEncryptionAlgorithm = expectedAlgorithm.getEncryptionAlgorithm();
		final EncryptionAlgorithm signatureEncryptionAlgorithm = signatureValue.getAlgorithm().getEncryptionAlgorithm();
		if (EncryptionAlgorithm.ECDSA.equals(expectedEncryptionAlgorithm) &&
				EncryptionAlgorithm.PLAIN_ECDSA.equals(signatureEncryptionAlgorithm)) {
			signatureValueBinaries = DSSASN1Utils.toStandardDSASignatureValue(signatureValue.getValue());

		} else if (EncryptionAlgorithm.PLAIN_ECDSA.equals(expectedEncryptionAlgorithm) &&
				EncryptionAlgorithm.ECDSA.equals(signatureEncryptionAlgorithm)) {
			signatureValueBinaries = DSSASN1Utils.toPlainDSASignatureValue(signatureValue.getValue());

		} else {
			throw new DSSException(String.format("Not supported conversion from SignatureAlgorithm '%s' defined within SignatureValue " +
					"to the target algorithm '%s'", signatureValue.getAlgorithm(), expectedAlgorithm));
		}
		newSignatureValue.setValue(signatureValueBinaries);
		return newSignatureValue;
	}

	/**
	 * This method returns a {@code SignatureAlgorithm} used to create the {@code signatureValue}
	 * NOTE: Only EdDSA algorithm is being returned by this method. For non-EdDSA or unsupported format, NULL will be returned
	 *
	 * @param signatureValue byte array representing the signature value
	 * @return {@link SignatureAlgorithm}
	 */
	public static SignatureAlgorithm getEdDSASignatureAlgorithm(byte[] signatureValue) {
		/*
		 * See RFC 8032 "Edwards-Curve Digital Signature Algorithm (EdDSA)"
		 * ...
		 * 4.  EdDSA uses small public keys (32 or 57 bytes) and
		 *     signatures (64 or 114 bytes) for Ed25519 and Ed448, respectively;
		 */
		if (signatureValue.length == 64) {
			return SignatureAlgorithm.ED25519;
		} else if (signatureValue.length == 114) {
			return SignatureAlgorithm.ED448;
		} else {
			LOG.warn("Unable to identify EdDSA Signature Algorithm!");
			return null;
		}
	}

	/**
	 * This method verifies the validity of thw provided {@code UserNotice} object
	 *
	 * @param userNotice {@link UserNotice} to check
	 * @throws IllegalArgumentException in case of an invalid configuration
	 */
	public static void assertSPUserNoticeConfigurationValid(final UserNotice userNotice) throws IllegalArgumentException {
		boolean organizationEmpty = Utils.isStringEmpty(userNotice.getOrganization());
		boolean noticeNumbersEmpty = userNotice.getNoticeNumbers() == null || userNotice.getNoticeNumbers().length == 0;
		if (organizationEmpty != noticeNumbersEmpty) {
			throw new IllegalArgumentException("Both Organization name and NoticeNumbers shall be defined " +
					"within the UserNotice configuration!");
		}
	}
	/**
	 * Transforms the given array of integers to a list of {@code BigInteger}s
	 *
	 * @param integers array of integers
	 * @return a list of {@link BigInteger}s
	 */
	public static List<BigInteger> toBigIntegerList(int[] integers) {
		List<BigInteger> bi = new ArrayList<>();
		for (int i : integers) {
			bi.add(BigInteger.valueOf(i));
		}
		return bi;
	}

	/**
	 * This method verifies if the given byte represents a line break character (new line or a carriage return)
	 *
	 * @param b byte to verify
	 * @return TRUE if the byte represents a line break char, FALSE otherwise
	 */
	public static boolean isLineBreakByte(byte b) {
		for (byte m : LINE_BREAK_CHARS) {
			if (b == m) {
				return true;
			}
		}
		return false;
	}

}
