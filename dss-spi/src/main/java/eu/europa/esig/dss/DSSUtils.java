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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
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
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.PolicyInformation;
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

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

public final class DSSUtils {

	private static final Logger logger = LoggerFactory.getLogger(DSSUtils.class);

	public static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----\n";
	public static final String CERT_END = "-----END CERTIFICATE-----";

	private static final BouncyCastleProvider securityProvider = new BouncyCastleProvider();

	/**
	 * FROM: Apache The index value when an element is not found in a list or
	 * array: {@code -1}. This value is returned by methods in this class and
	 * can also be used in comparisons with values returned by various method
	 * from {@link java.util.List}.
	 */
	public static final int INDEX_NOT_FOUND = -1;

	private static final CertificateFactory certificateFactory;
	public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

	public static final String DEFAULT_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/**
	 * The default date pattern: "yyyy-MM-dd"
	 */
	public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	private static JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

	static {

		try {

			Security.addProvider(securityProvider);

			certificateFactory = CertificateFactory.getInstance("X.509", "BC");

			jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
			jcaDigestCalculatorProviderBuilder.setProvider("BC");

		} catch (CertificateException e) {
			logger.error(e.getMessage(), e);
			throw new DSSException("Platform does not support X509 certificate", e);
		} catch (NoSuchProviderException e) {
			logger.error(e.getMessage(), e);
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
	 * Formats the given date-time using the default pattern:
	 * {@code DSSUtils.DEFAULT_DATE_TIME_FORMAT}
	 *
	 * @param date
	 * @return
	 */
	public static String formatDate(final Date date) {

		if (date != null) {
			final String stringDate = new SimpleDateFormat(DSSUtils.DEFAULT_DATE_TIME_FORMAT).format(date);
			return stringDate;
		}
		return StringUtils.EMPTY;
	}

	/**
	 * Converts the given string representation of the date using the
	 * {@code DEFAULT_DATE_TIME_FORMAT}.
	 *
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date}
	 * @throws DSSException
	 *             if the conversion is not possible the {@code DSSException} is
	 *             thrown.
	 */
	public static Date parseDate(final String dateString) throws DSSException {

		try {

			final SimpleDateFormat sdf = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
			final Date date = sdf.parse(dateString);
			return date;
		} catch (ParseException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Converts the given string representation of the date using the format
	 * pattern.
	 *
	 * @param format
	 *            the format to use
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date}
	 * @throws DSSException
	 *             if the conversion is not possible the {@code DSSException} is
	 *             thrown.
	 */
	public static Date parseDate(final String format, final String dateString) throws DSSException {

		try {

			final SimpleDateFormat sdf = new SimpleDateFormat(format);
			final Date date = sdf.parse(dateString);
			return date;
		} catch (ParseException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Converts the given string representation of the date using the
	 * {@code DEFAULT_DATE_TIME_FORMAT}. If an exception is frown durring the
	 * prsing then null is returned.
	 *
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date} or null if the parsing is not possible
	 */
	public static Date quietlyParseDate(final String dateString) throws DSSException {

		try {

			final SimpleDateFormat sdf = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
			final Date date = sdf.parse(dateString);
			return date;
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Converts an array of bytes into a String representing the hexadecimal
	 * values of each byte in order. The returned String will be double the
	 * length of the passed array, as it takes two characters to represent any
	 * given byte. If the input array is null then null is returned. The
	 * obtained string is converted to uppercase.
	 *
	 * @param value
	 * @return
	 */
	public static String toHex(final byte[] value) {

		return (value != null) ? new String(Hex.encodeHex(value, false)) : null;
	}

	/**
	 * Converts a hexadecimal character to an integer.
	 *
	 * @param ch
	 *            A character to convert to an integer digit
	 * @param index
	 *            The index of the character in the source
	 * @return An integer
	 * @throws DSSException
	 *             Thrown if ch is an illegal hex character
	 */
	protected static int toDigit(char ch, int index) throws DSSException {
		int digit = Character.digit(ch, 16);
		if (digit == -1) {
			throw new DSSException("Illegal hexadecimal character " + ch + " at index " + index);
		}
		return digit;
	}

	/**
	 * This method re-encode base 64 encoded string to base 64 encoded byte
	 * array.
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
	 * @param dssDocument
	 *            dss document to be encoded
	 * @return encoded base64 string
	 */
	public static String base64Encode(DSSDocument dssDocument) {
		final byte[] bytes = dssDocument.getBytes();
		final String base64EncodedBytes = Base64.encodeBase64String(bytes);
		return base64EncodedBytes;
	}

	/**
	 * @param certificate
	 * @return
	 */
	public static String base64Encode(final X509Certificate certificate) throws DSSException {

		try {
			final byte[] bytes = certificate.getEncoded();
			final String base64EncodedBytes = Base64.encodeBase64String(bytes);
			return base64EncodedBytes;
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Writes bytes from a {@code byte[]} to an {@code OutputStream}.
	 *
	 * @param data
	 *            the byte array to write, do not modify during output, null
	 *            ignored
	 * @param output
	 *            the {@code OutputStream} to write to
	 * @throws DSSException
	 *             if output is null or an I/O error occurs
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
	 * This method returns a file reference. The file path is normalised (OS
	 * independent)
	 *
	 * @param filePath
	 *            The path to the file.
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
	public static String convertToPEM(final CertificateToken cert) throws DSSException {
		final Base64 encoder = new Base64(64);
		final byte[] derCert = cert.getEncoded();
		final String pemCertPre = new String(encoder.encode(derCert));
		final String pemCert = CERT_BEGIN + pemCertPre + CERT_END;
		return pemCert;
	}

	/**
	 * This method loads a certificate from the given resource. The certificate
	 * must be DER-encoded and may be supplied in binary or printable (Base64)
	 * encoding. If the certificate is provided in Base64 encoding, it must be
	 * bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be
	 * bounded at the end by -----END CERTIFICATE-----. It throws an
	 * {@code DSSException} or return {@code null} when the certificate cannot
	 * be loaded.
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
	 * This method loads a certificate from the given location. The certificate
	 * must be DER-encoded and may be supplied in binary or printable (Base64)
	 * encoding. If the certificate is provided in Base64 encoding, it must be
	 * bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be
	 * bounded at the end by -----END CERTIFICATE-----. It throws an
	 * {@code DSSException} or return {@code null} when the certificate cannot
	 * be loaded.
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
	 * This method loads a certificate from the given location. The certificate
	 * must be DER-encoded and may be supplied in binary or printable (Base64)
	 * encoding. If the certificate is provided in Base64 encoding, it must be
	 * bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be
	 * bounded at the end by -----END CERTIFICATE-----. It throws an
	 * {@code DSSException} or return {@code null} when the certificate cannot
	 * be loaded.
	 *
	 * @param inputStream
	 *            input stream containing the certificate
	 * @return
	 */
	public static CertificateToken loadCertificate(final InputStream inputStream) throws DSSException {

		try {

			final X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
			return new CertificateToken(cert);
		} catch (CertificateException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads a certificate from the byte array. The certificate must
	 * be DER-encoded and may be supplied in binary or printable (Base64)
	 * encoding. If the certificate is provided in Base64 encoding, it must be
	 * bounded at the beginning by -----BEGIN CERTIFICATE-----, and must be
	 * bounded at the end by -----END CERTIFICATE-----. It throws an
	 * {@code DSSException} or return {@code null} when the certificate cannot
	 * be loaded.
	 *
	 * @param input
	 *            array of bytes containing the certificate
	 * @return
	 */
	public static CertificateToken loadCertificate(final byte[] input) throws DSSException {

		if (input == null) {
			throw new NullPointerException("X509 certificate");
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
	public static CertificateToken loadCertificateFromBase64EncodedString(final String base64Encoded) {

		final byte[] bytes = Base64.decodeBase64(base64Encoded);
		return loadCertificate(bytes);
	}

	/**
	 * This method loads the issuer certificate from the given location (AIA).
	 * The certificate must be DER-encoded and may be supplied in binary or
	 * printable (Base64) encoding. If the certificate is provided in Base64
	 * encoding, it must be bounded at the beginning by -----BEGIN
	 * CERTIFICATE-----, and must be bounded at the end by -----END
	 * CERTIFICATE-----. It throws an {@code DSSException} or return
	 * {@code null} when the certificate cannot be loaded.
	 *
	 * @param cert
	 *            certificate for which the issuer should be loaded
	 * @param loader
	 *            the loader to use
	 * @return
	 */
	public static CertificateToken loadIssuerCertificate(final CertificateToken cert, final DataLoader loader) {

		List<String> urls = getAccessLocations(cert);
		if (CollectionUtils.isEmpty(urls)) {
			logger.info("There is no AIA extension for certificate download.");
			return null;
		}

		if (loader == null) {
			logger.warn("There is no DataLoader defined to load Certificates from AIA extension (urls : " + urls + ")");
			return null;
		}

		for (String url : urls) {
			logger.debug("Loading certificate from {}", url);

			byte[] bytes = loader.get(url);
			if (ArrayUtils.isNotEmpty(bytes)) {
				try {
					logger.debug("Certificate : " + Base64.encodeBase64String(bytes));

					CertificateToken issuerCert = loadCertificate(bytes);
					if (issuerCert != null) {
						if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
							logger.info("There is AIA extension, but the issuer subject name and subject name does not match.");
							logger.info("CERT ISSUER    : " + cert.getIssuerX500Principal().toString());
							logger.info("ISSUER SUBJECT : " + issuerCert.getSubjectX500Principal().toString());
						}
						return issuerCert;
					}
				} catch (Exception e) {
					logger.warn("Unable to parse certficate from AIA (url:" + url + ") : " + e.getMessage(), e);
				}
			} else {
				logger.error("Unable to read data from {}.", url);
			}
		}

		return null;
	}

	/**
	 * This method return SKI bytes from certificate or null.
	 *
	 * @param x509Certificate
	 *            {@code X509Certificate}
	 * @return ski bytes from the given certificate
	 * @throws Exception
	 */
	public static byte[] getSki(final CertificateToken certificateToken) throws DSSException {

		try {
			final byte[] skiBytesFromCert = XMLX509SKI.getSKIBytesFromCert(certificateToken.getCertificate());
			return skiBytesFromCert;
		} catch (XMLSecurityException e) {
			return null;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	private static List<String> getAccessLocations(final CertificateToken certificate) {
		final byte[] authInfoAccessExtensionValue = certificate.getCertificate().getExtensionValue(Extension.authorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return null;
		}

		// Parse the extension
		ASN1Sequence asn1Sequence = null;
		try {
			asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(authInfoAccessExtensionValue);
		} catch (DSSException e) {
			return null;
		}

		AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(asn1Sequence);
		AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();

		List<String> locationsUrls = new ArrayList<String>();
		for (AccessDescription accessDescription : accessDescriptions) {
			if (X509ObjectIdentifiers.id_ad_caIssuers.equals(accessDescription.getAccessMethod())) {
				GeneralName gn = accessDescription.getAccessLocation();
				if (GeneralName.uniformResourceIdentifier == gn.getTagNo()) {
					DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
					locationsUrls.add(str.getString());
				}
			}
		}
		return locationsUrls;
	}

	/**
	 * This method loads a CRL from the given base 64 encoded string.
	 *
	 * @param base64Encoded
	 * @return
	 */
	public static X509CRL loadCRLBase64Encoded(final String base64Encoded) {

		final byte[] derEncoded = Base64.decodeBase64(base64Encoded);
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
	 * @param base64Encoded
	 *            base 64 encoded OCSP response
	 * @return {@code BasicOCSPResp}
	 * @throws IOException
	 * @throws OCSPException
	 */
	public static BasicOCSPResp loadOCSPBase64Encoded(final String base64Encoded) throws IOException, OCSPException {
		final byte[] derEncoded = Base64.decodeBase64(base64Encoded);
		final OCSPResp ocspResp = new OCSPResp(derEncoded);
		final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
		return basicOCSPResp;
	}

	public static List<String> getPolicyIdentifiers(final X509Certificate cert) {
		final byte[] certificatePolicies = cert.getExtensionValue(Extension.certificatePolicies.getId());
		if (certificatePolicies == null) {

			return Collections.emptyList();
		}
		ASN1Sequence seq = DSSASN1Utils.getAsn1SequenceFromDerOctetString(certificatePolicies);
		final List<String> policyIdentifiers = new ArrayList<String>();
		for (int ii = 0; ii < seq.size(); ii++) {

			final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
			// System.out.println("\t----> PolicyIdentifier: " +
			// policyInfo.getPolicyIdentifier().getId());
			policyIdentifiers.add(policyInfo.getPolicyIdentifier().getId());

		}
		return policyIdentifiers;
	}

	/**
	 * This method converts the {@code List} of {@code CertificateToken} to the
	 * {@code List} of {@code X509Certificate}.
	 *
	 * @param certTokens
	 *            the list of {@code CertificateToken} to be converted
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
	 * This method digests the given string with SHA1 algorithm and encode
	 * returned array of bytes as hex string.
	 *
	 * @param stringToDigest
	 *            Everything in the name
	 * @return hex encoded digest value
	 */
	public static String getSHA1Digest(final String stringToDigest) {

		final byte[] digest = getMessageDigest(DigestAlgorithm.SHA1).digest(stringToDigest.getBytes());
		return Hex.encodeHexString(digest);
	}

	/**
	 * This method digests the given {@code InputStream} with SHA1 algorithm and
	 * encode returned array of bytes as hex string.
	 *
	 * @param inputStream
	 * @return
	 */
	public static String getSHA1Digest(final InputStream inputStream) throws IOException {

		final byte[] bytes = IOUtils.toByteArray(inputStream);
		final byte[] digest = getMessageDigest(DigestAlgorithm.SHA1).digest(bytes);
		return Hex.encodeHexString(digest);
	}

	/**
	 * This method replaces in a string one pattern by another one without using
	 * regexp.
	 *
	 * @param string
	 * @param oldPattern
	 * @param newPattern
	 * @return
	 */
	public static StringBuffer replaceStrStr(final StringBuffer string, final String oldPattern, final String newPattern) {

		if ((string == null) || (oldPattern == null) || oldPattern.equals("") || (newPattern == null)) {

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
			final String digestAlgorithmOid = digestAlgorithm.getOid().getId();
			final MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithmOid);
			return messageDigest;
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException("Digest algorithm error: " + e.getMessage(), e);
		}
	}

	/**
	 * This method allows to digest the data in the {@code InputStream} with the
	 * given algorithm.
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

	public static byte[] digest(DigestAlgorithm digestAlgorithm, byte[]... data) {
		final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
		for (final byte[] bytes : data) {

			messageDigest.update(bytes);
		}
		final byte[] digestValue = messageDigest.digest();
		return digestValue;
	}

	/**
	 * This method digest and encrypt the given {@code InputStream} with
	 * indicated private key and signature algorithm. To find the signature
	 * object the list of registered security Providers, starting with the most
	 * preferred Provider is traversed.
	 *
	 * This method returns an array of bytes representing the signature value.
	 * Signature object that implements the specified signature algorithm. It
	 * traverses the list of registered security Providers, starting with the
	 * most preferred Provider. A new Signature object encapsulating the
	 * SignatureSpi implementation from the first Provider that supports the
	 * specified algorithm is returned. The {@code NoSuchAlgorithmException}
	 * exception is wrapped in a DSSException.
	 *
	 * @param javaSignatureAlgorithm
	 *            signature algorithm under JAVA form.
	 * @param privateKey
	 *            private key to use
	 * @param stream
	 *            the data to digest
	 * @return digested and encrypted array of bytes
	 */
	@Deprecated
	public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final InputStream stream) {

		try {

			logger.debug("Signature Algorithm: " + javaSignatureAlgorithm);
			final Signature signature = Signature.getInstance(javaSignatureAlgorithm);

			signature.initSign(privateKey);
			final byte[] buffer = new byte[4096];
			int count = 0;
			while ((count = stream.read(buffer)) > 0) {

				signature.update(buffer, 0, count);
			}
			final byte[] signatureValue = signature.sign();
			return signatureValue;
		} catch (GeneralSecurityException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method digest and encrypt the given {@code InputStream} with
	 * indicated private key and signature algorithm. To find the signature
	 * object the list of registered security Providers, starting with the most
	 * preferred Provider is traversed.
	 *
	 * This method returns an array of bytes representing the signature value.
	 * Signature object that implements the specified signature algorithm. It
	 * traverses the list of registered security Providers, starting with the
	 * most preferred Provider. A new Signature object encapsulating the
	 * SignatureSpi implementation from the first Provider that supports the
	 * specified algorithm is returned. The {@code NoSuchAlgorithmException}
	 * exception is wrapped in a DSSException.
	 *
	 * @param javaSignatureAlgorithm
	 *            signature algorithm under JAVA form.
	 * @param privateKey
	 *            private key to use
	 * @param bytes
	 *            the data to digest
	 * @return digested and encrypted array of bytes
	 */
	@Deprecated
	public static byte[] encrypt(final String javaSignatureAlgorithm, final PrivateKey privateKey, final byte[] bytes) {
		try {
			final Signature signature = Signature.getInstance(javaSignatureAlgorithm);
			signature.initSign(privateKey);
			signature.update(bytes);
			final byte[] signatureValue = signature.sign();
			return signatureValue;
		} catch (GeneralSecurityException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the {@code CertificateID} for the given certificate and its
	 * issuer's certificate.
	 *
	 * @param cert
	 *            {@code X509Certificate} for which the id is created
	 * @param issuerCert
	 *            {@code X509Certificate} issuer certificate of the {@code cert}
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
	 * Returns a {@code X509CertificateHolder} encapsulating the given
	 * {@code X509Certificate}.
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

	public static DigestCalculator getSHA1DigestCalculator() throws DSSException {

		try {
			final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
			final DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
			return digestCalculator;
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method opens the {@code URLConnection} using the given URL.
	 *
	 * @param url
	 *            URL to be accessed
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
	 * This method returns an {@code InputStream} which needs to be closed,
	 * based on {@code FileInputStream}.
	 *
	 * @param filePath
	 *            The path to the file to read
	 * @return an {@code InputStream} materialized by a {@code FileInputStream}
	 *         representing the contents of the file
	 * @throws DSSException
	 */
	public static InputStream toInputStream(final String filePath) throws DSSException {

		final File file = getFile(filePath);
		final InputStream inputStream = toInputStream(file);
		return inputStream;
	}

	/**
	 * This method returns an {@code InputStream} which needs to be closed,
	 * based on {@code FileInputStream}.
	 *
	 * @param file
	 *            {@code File} to read.
	 * @return an {@code InputStream} materialized by a {@code FileInputStream}
	 *         representing the contents of the file
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
	 * This method returns the {@code InputStream} based on the given
	 * {@code String} and char set. This stream does not need to be closed, it
	 * is based on {@code ByteArrayInputStream}.
	 *
	 * @param string
	 *            {@code String} to convert
	 * @param charset
	 *            char set to use
	 * @return the {@code InputStream} based on {@code ByteArrayInputStream}
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
	 * This method returns a {@code FileOutputStream} based on the provided path
	 * to the file.
	 *
	 * @param path
	 *            to the file
	 * @return {@code FileOutputStream}
	 */
	public static FileOutputStream toFileOutputStream(final String path) throws DSSException {

		try {
			return new FileOutputStream(path);
		} catch (FileNotFoundException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns an {@code InputStream} which does not need to be
	 * closed, based on {@code ByteArrayInputStream}.
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
	 *
	 * Reads the contents of a file into a byte array. The file is always
	 * closed.
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
			return IOUtils.toByteArray(in);
		} finally {
			IOUtils.closeQuietly(in);
		}
	}

	/**
	 * FROM: Apache
	 *
	 * Opens a {@link java.io.FileInputStream} for the specified file, providing
	 * better error messages than simply calling
	 * {@code new FileInputStream(file)}.
	 *
	 * At the end of the method either the stream will be successfully opened,
	 * or an exception will have been thrown.
	 *
	 * An exception is thrown if the file does not exist. An exception is thrown
	 * if the file object exists but is a directory. An exception is thrown if
	 * the file exists but cannot be read.
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
			throw new NullPointerException();
		}
		try {
			final byte[] bytes = IOUtils.toByteArray(inputStream);
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static String toString(final byte[] bytes) {

		if (bytes == null) {

			throw new NullPointerException();
		}
		final String string = new String(bytes);
		return string;
	}

	/**
	 * This method saves the given array of {@code byte} to the provided
	 * {@code File}.
	 *
	 * @param bytes
	 *            to save
	 * @param file
	 * @throws DSSException
	 */
	public static void saveToFile(final byte[] bytes, final File file) throws DSSException {

		file.getParentFile().mkdirs();
		try {

			final FileOutputStream fileOutputStream = new FileOutputStream(file);
			final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
			IOUtils.copy(inputStream, fileOutputStream);
			IOUtils.closeQuietly(inputStream);
			IOUtils.closeQuietly(fileOutputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method saves the given {@code InputStream} to a file representing by
	 * the provided path. The {@code InputStream} is not closed.
	 *
	 * @param inputStream
	 *            {@code InputStream} to save
	 * @param path
	 *            the path to the file to be created
	 */
	public static void saveToFile(final InputStream inputStream, final String path) throws IOException {

		final FileOutputStream fileOutputStream = toFileOutputStream(path);
		IOUtils.copy(inputStream, fileOutputStream);
		IOUtils.closeQuietly(fileOutputStream);
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

	public static CertificateToken getCertificate(final X509CertificateHolder x509CertificateHolder) {

		try {

			final Certificate certificate = x509CertificateHolder.toASN1Structure();
			final X509CertificateObject x509CertificateObject = new X509CertificateObject(certificate);
			return new CertificateToken(x509CertificateObject);
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
	public static String getDeterministicId(final Date signingTime, final String id) {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			if (signingTime != null) {
				baos.write(Long.toString(signingTime.getTime()).getBytes());
			}
			baos.write(id.getBytes());

			final String deterministicId = "id-" + getMD5Digest(baos);
			return deterministicId;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns a Hex encoded of the MD5 digest of ByteArrayOutputStream
	 * 
	 * @param baos
	 * @return
	 */
	public static String getMD5Digest(ByteArrayOutputStream baos) {
		try {
			MessageDigest digest = MessageDigest.getInstance("MD5");
			digest.update(baos.toByteArray());
			byte[] digestValue = digest.digest();
			return Hex.encodeHexString(digestValue);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public static Date getLocalDate(final Date gtmDate, final Date localDate) {

		final Date newLocalDate = new Date(gtmDate.getTime() + TimeZone.getDefault().getOffset(localDate.getTime()));
		return newLocalDate;
	}

	public static long toLong(final byte[] bytes) {

		// Long.valueOf(new String(bytes)).longValue();
		ByteBuffer buffer = ByteBuffer.allocate(8);
		buffer.put(bytes, 0, Long.SIZE / 8);
		// TODO: (Bob: 2014 Jan 22) To be checked if it is not platform
		// dependent?
		buffer.flip();// need flip
		return buffer.getLong();
	}

	public static void delete(final File file) {
		if (file != null) {
			file.delete();
		}
	}

	/**
	 * This method returns the {@code X500Principal} corresponding to the given
	 * string or {@code null} if the conversion is not possible.
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
			logger.warn(e.getMessage());
		}
		return null;
	}

	/**
	 * This method compares two {@code X500Principal}s.
	 * {@code X500Principal.CANONICAL} and {@code X500Principal.RFC2253} forms
	 * are compared. TODO: (Bob: 2014 Feb 20) To be investigated why the
	 * standard equals does not work!?
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
		// System.out.println(">>> " + x500Principal.getName() + "-------" +
		// utf8Name);
		final X500Principal x500PrincipalNormalized = new X500Principal(utf8Name);
		return x500PrincipalNormalized;
	}

	/**
	 * @param x500Principal
	 *            to be normalized
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
	 * The distinguished name is regenerated to avoid problems related to the
	 * {@code X500Principal} encoding.
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
		 * RFC 4514 LDAP: Distinguished Names 2.1. Converting the RDNSequence
		 *
		 * If the RDNSequence is an empty sequence, the result is the empty or
		 * zero-length string.
		 *
		 * Otherwise, the output consists of the string encodings of each
		 * RelativeDistinguishedName in the RDNSequence (according to Section
		 * 2.2), starting with the last element of the sequence and moving
		 * backwards toward the first. ...
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
				// System.out.println(">>> " + attributeType.toString() + "=" +
				// attributeValue.getClass().getSimpleName() + "[" + string +
				// "]");
				if (stringBuilder.length() != 0) {
					stringBuilder.append(',');
				}
				stringBuilder.append(attributeType).append('=').append(string);
			}
		}
		// final X500Name x500Name = X500Name.getInstance(encoded);
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
			logger.error("!!!*******!!! This encoding is unknown: " + attributeValue.getClass().getSimpleName());
			string = attributeValue.toString();
			logger.error("!!!*******!!! value: " + string);
		}
		return string;
	}

	/**
	 * This method return the unique message id which can be used for
	 * translation purpose.
	 *
	 * @param message
	 *            the {@code String} message on which the unique id is
	 *            calculated.
	 * @return the unique id
	 */
	public static String getMessageId(final String message) {

		final String message_ = message./* replace('\'', '_'). */toLowerCase().replaceAll("[^a-z_]", " ");
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
	 * Returns an estimate of the number of bytes that can be read (or skipped
	 * over) from this input stream without blocking by the next invocation of a
	 * method for this input stream. The next invocation might be the same
	 * thread or another thread. A single read or skip of this many bytes will
	 * not block, but may read or skip fewer bytes.
	 *
	 *
	 * the total number of bytes in the stream, many will not. It is never
	 * correct to use the return value of this method to allocate a buffer
	 * intended to hold all data in this stream.
	 *
	 *
	 * {@link IOException} if this input stream has been closed by invoking the
	 * {@link InputStream#close()} method.
	 *
	 *
	 * returns {@code 0}.
	 *
	 *
	 *
	 * @return an estimate of the number of bytes that can be read (or skipped
	 *         over) from this input stream without blocking or {@code 0} when
	 *         it reaches the end of the input stream.
	 * @throws DSSException
	 *             if IOException occurs (if an I/O error occurs)
	 */
	public static int available(final InputStream is) throws DSSException {

		try {
			return is.available();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * replaces e.g. "\xc3\xa9" with "é"
	 *
	 * @param s
	 *            the input
	 * @return the output
	 */
	public static String unescapeMultiByteUtf8Literals(final String s) {
		try {
			final String q = new String(unescapePython(s.getBytes("UTF-8")), "UTF-8");
			// if (!q.equals(s)) {
			// LOG.log(Level.SEVERE, "multi byte utf literal found:\n" +
			// "  orig = " + s + "\n" +
			// "  escp = " + q
			// );
			// }
			return q;
		} catch (Exception e) {
			// LOG.log(Level.SEVERE,
			// "Could not unescape multi byte utf literal - will use original input: "
			// + s, e);
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
			if ((posSource + 1) >= escaped.length) {
				throw new Exception("String incorrectly escaped, ends with escape character.");
			}
			// deal with hex first
			if (escaped[posSource + 1] == 'x') {
				// if there's no next byte, throw incorrect encoding error
				if ((posSource + 3) >= escaped.length) {
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

	/**
	 * @param x509Certificate
	 * @return
	 */
	public static List<String> getQCStatementsIdList(final X509Certificate x509Certificate) {

		final List<String> extensionIdList = new ArrayList<String>();
		final byte[] qcStatement = x509Certificate.getExtensionValue(Extension.qCStatements.getId());
		if (qcStatement != null) {

			final ASN1Sequence seq = DSSASN1Utils.getAsn1SequenceFromDerOctetString(qcStatement);
			// Sequence of QCStatement
			for (int ii = 0; ii < seq.size(); ii++) {

				final QCStatement statement = QCStatement.getInstance(seq.getObjectAt(ii));
				extensionIdList.add(statement.getStatementId().getId());
			}
		}
		return extensionIdList;
	}

	/**
	 * This method closes the given {@code OutputStream} and throws a
	 * {@code DSSException} when the operation fails.
	 *
	 * @param outputStream
	 *            {@code OutputStream} to be closed
	 */
	public static void close(final OutputStream outputStream) {

		try {
			outputStream.close();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the file extension based on the position of the '.' in the path.
	 * The paths as "xxx.y/toto" are not handled.
	 *
	 * @param path
	 *            to be analysed
	 * @return the file extension or null
	 */
	@Deprecated
	public static String getFileExtension(final String path) {

		return MimeType.getFileExtension(path);
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
	 * This method returns the summary of the given exception. The analysis of
	 * the stack trace stops when the provided class is found.
	 *
	 * @param exception
	 *            {@code Exception} to summarize
	 * @param javaClass
	 *            {@code Class}
	 * @return {@code String} containing the summary message
	 */
	public static String getSummaryMessage(final Exception exception, final Class<?> javaClass) {

		final String javaClassName = javaClass.getName();
		final StackTraceElement[] stackTrace = exception.getStackTrace();
		String message = "See log file for full stack trace.\n";
		message += exception.toString() + '\n';
		for (StackTraceElement element : stackTrace) {

			final String className = element.getClassName();
			if (className.equals(javaClassName)) {

				message += element.toString() + '\n';
				break;
			}
			message += element.toString() + '\n';
		}
		return message;
	}

	/**
	 * Reads maximum {@code headerLength} bytes from {@code dssDocument} to the
	 * given {@code byte} array.
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

		final InputStream inputStream = dssDocument.openStream();
		try {
			int read = inputStream.read(destinationByteArray, 0, headerLength);
			return read;
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	/**
	 * Gets a difference between two dates
	 *
	 * @param date1
	 *            the oldest date
	 * @param date2
	 *            the newest date
	 * @param timeUnit
	 *            the unit in which you want the diff
	 * @return the difference value, in the provided unit
	 */
	public static long getDateDiff(final Date date1, final Date date2, final TimeUnit timeUnit) {

		long diff = date2.getTime() - date1.getTime();
		return timeUnit.convert(diff, TimeUnit.MILLISECONDS);
	}

	/**
	 * This method returns an encoded representation of the
	 * {@code X509CertificateHolder}.
	 *
	 * @param x509CertificateHolder
	 *            {@code X509CertificateHolder} to be encoded
	 * @return array of {@code byte}s
	 */
	@Deprecated
	public static byte[] getEncoded(final X509CertificateHolder x509CertificateHolder) {

		try {
			return x509CertificateHolder.getEncoded();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Concatenates all the arrays into a new array. The new array contains all
	 * of the element of each array followed by all of the elements of the next
	 * array. When an array is returned, it is always a new array.
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
}