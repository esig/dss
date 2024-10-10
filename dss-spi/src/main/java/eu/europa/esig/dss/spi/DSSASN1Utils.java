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
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.SignerIdentifier;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.BigIntegers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Utility class that contains some ASN1 related method.
 *
 */
public final class DSSASN1Utils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSASN1Utils.class);

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	/**
	 * This class is a utility class and cannot be instantiated.
	 */
	private DSSASN1Utils() {
		// empty
	}

	/**
	 * This method returns {@code T extends ASN1Primitive} created from array of bytes. The {@code IOException} is
	 * transformed in {@code DSSException}.
	 *
	 * @param bytes
	 *            array of bytes to be transformed to {@code ASN1Primitive}
	 * @param <T>
	 *            the expected return type
	 * @return new {@code T extends ASN1Primitive}
	 */
	@SuppressWarnings("unchecked")
	public static <T extends ASN1Primitive> T toASN1Primitive(final byte[] bytes) {
		try {
			return (T) ASN1Primitive.fromByteArray(bytes);
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot convert binaries to ASN1Primitive : %s", e.getMessage()), e);
		}
	}

	/**
	 * This method checks if a given {@code DEROctetString} is null.
	 *
	 * @param derOctetString
	 *            the {@code DEROctetString} to check
	 * @return true if the {@code DEROctetString} contains DERNull
	 */
	public static boolean isDEROctetStringNull(final DEROctetString derOctetString) {
		final byte[] derOctetStringBytes = derOctetString.getOctets();
		final ASN1Primitive asn1Null = toASN1Primitive(derOctetStringBytes);
		return DERNull.INSTANCE.equals(asn1Null);
	}

	/**
	 * This method returns DER encoded ASN1 attribute. The {@code IOException} is
	 * transformed in {@code DSSException}.
	 *
	 * @param asn1Encodable
	 *            asn1Encodable to be DER encoded
	 * @return array of bytes representing the DER encoded asn1Encodable
	 */
	public static byte[] getDEREncoded(ASN1Encodable asn1Encodable) {
		return getEncoded(asn1Encodable, ASN1Encoding.DER);
	}

	/**
	 * This method returns BER encoded ASN1 attribute. The {@code IOException} is
	 * transformed in {@code DSSException}.
	 *
	 * @param asn1Encodable
	 *            asn1Encodable to be BER encoded
	 * @return array of bytes representing the BER encoded asn1Encodable
	 */
	public static byte[] getBEREncoded(ASN1Encodable asn1Encodable) {
		return getEncoded(asn1Encodable, ASN1Encoding.BER);
	}

	/**
	 * This method returns encoded ASN1 attribute. The {@code IOException} is
	 * transformed in {@code DSSException}.
	 *
	 * @param asn1Encodable
	 *            asn1Encodable to be the given encoding
	 * @param encoding
	 *            the expected encoding
	 * @return array of bytes representing the encoded asn1Encodable
	 */
	private static byte[] getEncoded(ASN1Encodable asn1Encodable, String encoding) {
		try {
			return asn1Encodable.toASN1Primitive().getEncoded(encoding);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to encode to %s. Reason : %s", encoding, e.getMessage()), e);
		}
	}

	/**
	 * Gets the DER-encoded binaries of the {@code BasicOCSPResp}
	 *
	 * @param basicOCSPResp {@link BasicOCSPResp}
	 * @return DER-encoded binaries
	 */
	public static byte[] getEncoded(BasicOCSPResp basicOCSPResp) {
		try {
			BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(basicOCSPResp.getEncoded());
			return getDEREncoded(basicOCSPResponse);
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot retrieve DER encoded binaries of BasicOCSPResp : %s", e.getMessage()), e);
		}
	}

	/**
	 * Converts {@code ASN1GeneralizedTime} to {@code Date}
	 *
	 * @param asn1Date {@link ASN1GeneralizedTime}
	 * @return {@link Date}
	 */
	public static Date toDate(final ASN1GeneralizedTime asn1Date) {
		try {
			return asn1Date.getDate();
		} catch (ParseException e) {
			throw new DSSException(String.format("Cannot parse Date : %s", e.getMessage()), e);
		}
	}

	/**
	 * Reads {@code ASN1OctetString} value and returns
	 *
	 * @param value {@link ASN1OctetString}
	 * @return {@link String}
	 */
	public static String toString(final ASN1OctetString value) {
		return new String(value.getOctets());
	}

	/**
	 * Returns an ASN.1 encoded bytes representing the {@code TimeStampToken}
	 *
	 * @param timeStampToken
	 *                       {@code TimeStampToken}
	 * @return the DER encoded {@code TimeStampToken}
	 */
	public static byte[] getEncoded(final TimeStampToken timeStampToken) {
		return getEncoded(timeStampToken.toCMSSignedData());
	}

	/**
	 * Returns an ASN.1 encoded bytes representing the {@code CMSSignedData}
	 *
	 * @param cmsSignedData
	 *                       {@code CMSSignedData}
	 * @return the binary of the {@code CMSSignedData} @ if the {@code
	 * CMSSignedData} encoding fails
	 */
	public static byte[] getEncoded(final CMSSignedData cmsSignedData) {
		try {
			return cmsSignedData.getEncoded();
		} catch (IOException e) {
			throw new DSSException("Unable to encode to DER", e);
		}
	}

	/**
	 * Gets the DER encoded binaries of {@code TimeStampToken}
	 *
	 * @param timeStampToken {@link TimeStampToken}
	 * @return DER encoded binaries
	 */
	public static byte[] getDEREncoded(final TimeStampToken timeStampToken) {
		return getDEREncoded(timeStampToken.toCMSSignedData());
	}

	/**
	 * Returns the ASN.1 encoded representation of {@code CMSSignedData}.
	 *
	 * @param data
	 *             the CMSSignedData to be encoded
	 * @return the DER encoded CMSSignedData
	 */
	public static byte[] getDEREncoded(final CMSSignedData data) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			final ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(baos, ASN1Encoding.DER);
			asn1OutputStream.writeObject(data.toASN1Structure());
			asn1OutputStream.close();
			return baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Unable to encode to DER", e);
		}
	}

	/**
	 * Returns the ASN.1 encoded representation of {@code TimestampBinary}.
	 *
	 * @param timestampBinary
	 *             the {@link TimestampBinary} to be encoded
	 * @return the DER encoded timestampBinary
	 */
	public static byte[] getDEREncoded(final TimestampBinary timestampBinary) {
		return getDEREncoded(timestampBinary.getBytes());
	}

	/**
	 * Returns the ASN.1 encoded representation of {@code byte} array.
	 *
	 * @param bytes
	 *             the binary array to encode
	 * @return the DER encoded bytes
	 */
	public static byte[] getDEREncoded(final byte[] bytes) {
		try {
			return getDEREncoded(ASN1Primitive.fromByteArray(bytes));
		} catch (IOException e) {
			throw new DSSException("Unable to encode to DER", e);
		}
	}

	/**
	 * This method returns the {@code ASN1Sequence} encapsulated in
	 * {@code DEROctetString}. The {@code DEROctetString} is represented as
	 * {@code byte} array.
	 *
	 * @param bytes
	 *              {@code byte} representation of {@code DEROctetString}
	 * @return encapsulated {@code ASN1Sequence} or exception in case of a decoding problem
	 */
	public static ASN1Sequence getAsn1SequenceFromDerOctetString(byte[] bytes) {
		return getASN1Sequence(getDEROctetStringContent(bytes));
	}

	private static ASN1Sequence getASN1Sequence(byte[] bytes) {
		try (ASN1InputStream input = new ASN1InputStream(bytes)) {
			return (ASN1Sequence) input.readObject();
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the ASN1Sequence", e);
		}
	}

	/**
	 * This method returns the {@code ASN1Integer} encapsulated in
	 * {@code DEROctetString}. The {@code DEROctetString} is represented as
	 * {@code byte} array.
	 *
	 * @param bytes
	 *              {@code byte} representation of {@code DEROctetString}
	 * @return encapsulated {@code ASN1Integer} or exception in case of a decoding problem
	 */
	public static ASN1Integer getAsn1IntegerFromDerOctetString(byte[] bytes) {
		return getASN1Integer(getDEROctetStringContent(bytes));
	}

	private static ASN1Integer getASN1Integer(byte[] bytes) {
		try (ASN1InputStream input = new ASN1InputStream(bytes)) {
			return (ASN1Integer) input.readObject();
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the ASN1Integer", e);
		}
	}

	private static byte[] getDEROctetStringContent(byte[] bytes) {
		try (ASN1InputStream input = new ASN1InputStream(bytes)) {
			final DEROctetString s = (DEROctetString) input.readObject();
			return s.getOctets();
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the DEROctetString content", e);
		}
	}

	/**
	 * This method computes the digest of an ASN1 signature policy (used in CAdES)
	 *
	 * TS 101 733 5.8.1 : If the signature policy is defined using ASN.1, then the hash is calculated on the value
	 * without the outer type and length
	 * fields, and the hashing algorithm shall be as specified in the field sigPolicyHash.
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param policyBytes
	 *            the ASN.1 policy content
	 * @return the expected digest value
	 */
	public static byte[] getAsn1SignaturePolicyDigest(DigestAlgorithm digestAlgorithm, byte[] policyBytes) {
		ASN1Sequence asn1Seq = toASN1Primitive(policyBytes);

		ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Seq.getObjectAt(0);
		AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
		ASN1Sequence signPolicyInfo = (ASN1Sequence) asn1Seq.getObjectAt(1);

		byte[] hashAlgorithmDEREncoded = getDEREncoded(signPolicyHashAlgIdentifier);
		byte[] signPolicyInfoDEREncoded = getDEREncoded(signPolicyInfo);
		return DSSUtils.digest(digestAlgorithm, hashAlgorithmDEREncoded, signPolicyInfoDEREncoded);
	}

	/**
	 * Gets the ASN.1 algorithm identifier structure corresponding to the algorithm 
	 * found in the provided Timestamp Hash Index Table, if such algorithm is present
	 *
	 * @param atsHashIndexValue
	 *            ats-hash-index table from a timestamp
	 * @return the ASN.1 algorithm identifier structure
	 */
	public static AlgorithmIdentifier getAlgorithmIdentifier(final ASN1Sequence atsHashIndexValue) {
		if (atsHashIndexValue != null && atsHashIndexValue.size() > 3) {
			final int algorithmIndex = 0;
			final ASN1Encodable asn1Encodable = atsHashIndexValue.getObjectAt(algorithmIndex);
			
			if (asn1Encodable instanceof ASN1Sequence) {
				final ASN1Sequence asn1Sequence = (ASN1Sequence) asn1Encodable;
				return AlgorithmIdentifier.getInstance(asn1Sequence);
			} else if (asn1Encodable instanceof ASN1ObjectIdentifier) {
				// TODO (16/11/2014): The relevance and usefulness of the test case must be checked (do the signatures
				// like this exist?)
				ASN1ObjectIdentifier derObjectIdentifier = ASN1ObjectIdentifier.getInstance(asn1Encodable);
				return new AlgorithmIdentifier(derObjectIdentifier);
			}
		}
		return null;
	}

	/**
	 * Gets the ASN.1 algorithm identifier structure corresponding to a digest algorithm
	 *
	 * @param digestAlgorithm
	 *            the digest algorithm to encode
	 * @return the ASN.1 algorithm identifier structure
	 */
	public static AlgorithmIdentifier getAlgorithmIdentifier(DigestAlgorithm digestAlgorithm) {

		/*
		 * The recommendation (cf. RFC 3380 section 2.1) is to omit the parameter for SHA-1, but some implementations
		 * still expect a
		 * NULL there. Therefore we always include a NULL parameter even with SHA-1, despite the recommendation, because
		 * the RFC
		 * states that implementations SHOULD support it as well anyway
		 */
		final ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(digestAlgorithm.getOid());
		return new AlgorithmIdentifier(asn1ObjectIdentifier, DERNull.INSTANCE);
	}

	/**
	 * Returns list of {@code DEROctetString} from an {@code ASN1Sequence}
	 * Useful when needed to get a list of hash values
	 * 
	 * @param asn1Sequence {@link ASN1Sequence} to get list from
	 * @return list of {@link DEROctetString}s
	 */
	@SuppressWarnings("unchecked")
	public static List<DEROctetString> getDEROctetStrings(final ASN1Sequence asn1Sequence) {
		final List<DEROctetString> derOctetStrings = new ArrayList<>();
		if (asn1Sequence != null) {
			derOctetStrings.addAll(Collections.list(asn1Sequence.getObjects()));
		}
		return derOctetStrings;
	}

	/**
	 * Computes SHA-1 hash of the {@code certificateToken}'s public key
	 * 
	 * @param certificateToken
	 *                         {@link CertificateToken} to compute digest for
	 * @return byte array of public key's SHA-1 hash
	 */
	public static byte[] computeSkiFromCert(final CertificateToken certificateToken) {
		return computeSkiFromCertPublicKey(certificateToken.getPublicKey());
	}

	/**
	 * Computes SHA-1 hash of the given {@code publicKey}'s
	 * @param publicKey {@link PublicKey} to compute digest for
	 * @return byte array of public key's SHA-1 hash
	 */
	public static byte[] computeSkiFromCertPublicKey(final PublicKey publicKey) {
		try {
			DLSequence seq = (DLSequence) ASN1Primitive.fromByteArray(publicKey.getEncoded());
			DERBitString item = (DERBitString) seq.getObjectAt(1);
			return DSSUtils.digest(DigestAlgorithm.SHA1, item.getOctets());

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to compute ski from public key : %s", e.getMessage()), e);
		}
	}
	
	/**
	 * Checks if the provided ski matches to a ski computed from a certificateToken's public key
	 * 
	 * @param ski a byte array representing ski value (SHA-1 of the public key)
	 * @param certificateToken {@link CertificateToken} to check
	 * @return TRUE if the SKI equals, FALSE otherwise
	 */
	public static boolean isSkiEqual(final byte[] ski, final CertificateToken certificateToken) {
		byte[] certSki = computeSkiFromCert(certificateToken);
        return Arrays.equals(certSki, ski);
	}

	/**
	 * Returns a {@code X509CertificateHolder} encapsulating the given {@code X509Certificate}.
	 * 
	 * @param certToken
	 *            the certificate to be encapsulated
	 * @return a X509CertificateHolder holding this certificate
	 */
	public static X509CertificateHolder getX509CertificateHolder(CertificateToken certToken) {
		try {
			return new X509CertificateHolder(certToken.getEncoded());
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to instantiate a X509CertificateHolder : %s", e.getMessage()), e);
		}
	}

	/**
	 * Extract the certificate token from {@code X509CertificateHolder}
	 *
	 * @param x509CertificateHolder {@link X509CertificateHolder}
	 * @return {@link CertificateToken}
	 */
	public static CertificateToken getCertificate(final X509CertificateHolder x509CertificateHolder) {
		try {
			JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(DSSSecurityProvider.getSecurityProviderName());
			X509Certificate x509Certificate = converter.getCertificate(x509CertificateHolder);
			return new CertificateToken(x509Certificate);

		} catch (CertificateException e) {
			throw new DSSException(String.format(
					"Unable to get a CertificateToken from X509CertificateHolder : %s", e.getMessage()), e);
		}
	}

	/**
	 * This method transforms token's signerId into a {@code SignerIdentifier}
	 * object
	 * 
	 * @param signerId {@link SignerId} to be transformed
	 * @return {@link SignerIdentifier}
	 */
	public static SignerIdentifier toSignerIdentifier(SignerId signerId) {
		X500Principal issuerX500Principal = toX500Principal(signerId.getIssuer());
		return toSignerIdentifier(issuerX500Principal, signerId.getSerialNumber(), signerId.getSubjectKeyIdentifier());
	}
	
	/**
	 * Transforms x500Name to X500Principal
	 * 
	 * @param x500Name {@link X500Name}
	 * @return {@link X500Principal}
	 */
	public static X500Principal toX500Principal(X500Name x500Name) {
		if (x500Name == null) {
			return null;
		}
		try {
			return new X500Principal(x500Name.getEncoded());
		} catch (IOException e) {
			throw new DSSException(String.format("Cannot extract X500Principal! Reason : %s", e.getMessage()), e);
		}
	}
	
	/**
	 * This method transforms token's issuer and serial number information into a
	 * {@code CertificateIdentifier} object
	 * 
	 * @param issuerX500Principal {@link X500Principal} of the issuer
	 * @param serialNumber        {@link BigInteger} of the token
	 * @param ski                 a byte array representing a SubjectKeyIdentifier
	 *                            (SHA-1 digest of the public key)
	 * @return {@link SignerIdentifier}
	 */
	public static SignerIdentifier toSignerIdentifier(final X500Principal issuerX500Principal, final BigInteger serialNumber, final byte[] ski) {
		SignerIdentifier signerIdentifier = new SignerIdentifier();
		signerIdentifier.setIssuerName(issuerX500Principal);
		signerIdentifier.setSerialNumber(serialNumber);
		signerIdentifier.setSki(ski);
		return signerIdentifier;
	}

	/**
	 * This method returns a new IssuerSerial based on the certificate token
	 *
	 * @param certToken
	 *            the certificate token
	 * @return a IssuerSerial
	 */
	public static IssuerSerial getIssuerSerial(final CertificateToken certToken) {
		final X500Name issuerX500Name = getX509CertificateHolder(certToken).getIssuer();
		final GeneralName generalName = new GeneralName(issuerX500Name);
		final GeneralNames generalNames = new GeneralNames(generalName);
		final BigInteger serialNumber = certToken.getCertificate().getSerialNumber();
		return new IssuerSerial(generalNames, serialNumber);
	}

	/**
	 * This method compares two {@code X500Principal}s. {@code X500Principal.CANONICAL} and
	 * {@code X500Principal.RFC2253} forms are compared.
	 *
	 * @param firstX500Principal
	 *            the first X500Principal object to be compared
	 * @param secondX500Principal
	 *            the second X500Principal object to be compared
	 * @return true if the two parameters contain the same key/values
	 */
	public static boolean x500PrincipalAreEquals(final X500Principal firstX500Principal, final X500Principal secondX500Principal) {
		if ((firstX500Principal == null) || (secondX500Principal == null)) {
			return false;
		}
		if (firstX500Principal.equals(secondX500Principal)) {
			return true;
		}
		final Map<String, String> firstStringStringHashMap = get(firstX500Principal);
		final Map<String, String> secondStringStringHashMap = get(secondX500Principal);
		return firstStringStringHashMap.equals(secondStringStringHashMap);
	}

	/**
	 * Gets a map of X500 attribute names and the values
	 *
	 * @param x500Principal {@link X500Principal}
	 * @return a map of X500 attribute names and the values
	 */
	public static Map<String, String> get(final X500Principal x500Principal) {
		Map<String, String> treeMap = new HashMap<>();
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

	/**
	 * Converts {@code ASN1Encodable} to a {@code String} value.
	 * The method preserves the object class and structure and returns hash-encoded String value,
	 * unless the object is an instance of {@code ASN1String}.
	 *
	 * @param attributeValue {@link ASN1Encodable} to read
	 * @return {@link String} value
	 */
	public static String getString(ASN1Encodable attributeValue) {
		if (attributeValue == null) {
			LOG.warn("Null attribute has been provided!");
			return null;
		}

		try {
			return IETFUtils.valueToString(attributeValue);
		} catch (Exception e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to handle attribute of class '{}' : {}", attributeValue.getClass().getName(), e.getMessage());
			} else {
				LOG.warn("Unable to handle attribute : {}", e.getMessage());
			}
			return null;
		}
	}

	/**
	 * Extract attribute with the {@code identifier} from {@code X500PrincipalHelper}
	 *
	 * @param identifier {@link ASN1ObjectIdentifier} oid of the attribute to get value
	 * @param principal {@link X500PrincipalHelper} to extract the attribute value from
	 * @return {@link String} value
	 */
	public static String extractAttributeFromX500Principal(ASN1ObjectIdentifier identifier, X500PrincipalHelper principal) {
		final X500Name x500Name = X500Name.getInstance(principal.getEncoded());
		RDN[] rdns = x500Name.getRDNs(identifier);
		for (RDN rdn : rdns) {
			if (rdn.isMultiValued()) {
				AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
				for (AttributeTypeAndValue typeAndValue : typesAndValues) {
					if (identifier.equals(typeAndValue.getType())) {
						return typeAndValue.getValue().toString();
					}
				}
			} else {
				AttributeTypeAndValue typeAndValue = rdn.getFirst();
				if (identifier.equals(typeAndValue.getType())) {
					return typeAndValue.getValue().toString();
				}
			}
		}
		return null;
	}

	/**
	 * Extracts the Subject Common name from the certificate token
	 *
	 * @param cert {@link CertificateToken}
	 * @return {@link String}
	 */
	public static String getSubjectCommonName(CertificateToken cert) {
		return extractAttributeFromX500Principal(BCStyle.CN, cert.getSubject());
	}

	/**
	 * Extracts the pretty printed name of the certificate token
	 *
	 * @param cert {@link CertificateToken}
	 * @return {@link String}
	 */
	public static String getHumanReadableName(CertificateToken cert) {
		return getHumanReadableName(cert.getSubject());
	}

	/**
	 * Extracts the pretty printed name from the {@code X500PrincipalHelper}
	 *
	 * @param x500PrincipalHelper {@link X500PrincipalHelper}
	 * @return {@link String}
	 */
	public static String getHumanReadableName(X500PrincipalHelper x500PrincipalHelper) {
		return firstNotNull(x500PrincipalHelper, BCStyle.CN, BCStyle.GIVENNAME, BCStyle.SURNAME, BCStyle.NAME,
				BCStyle.PSEUDONYM, BCStyle.O, BCStyle.OU);
	}

	private static String firstNotNull(X500PrincipalHelper x500PrincipalHelper, ASN1ObjectIdentifier... oids) {
		for (ASN1ObjectIdentifier oid : oids) {
			String value = extractAttributeFromX500Principal(oid, x500PrincipalHelper);
			if (value != null) {
				return value;
			}
		}
		return null;
	}

	/**
	 * Returns the first {@code SignerInformation} extracted from {@code CMSSignedData}.
	 *
	 * @param cms
	 *            CMSSignedData
	 * @return returns {@code SignerInformation}
	 */
	public static SignerInformation getFirstSignerInformation(final CMSSignedData cms) {
		final Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
		if (signers.size() > 1) {
			LOG.warn("!!! The framework handles only one signer (SignerInformation) !!!");
		}
		return signers.iterator().next();
	}

	/**
	 * Checks if the byte defines an ASN1 Sequence
	 *
	 * @param tagByte byte to check
	 * @return TRUE if the byte defines an ASN1 Sequence, FALSE otherwise
	 */
	public static boolean isASN1SequenceTag(byte tagByte) {
		// BERTags.SEQUENCE | BERTags.CONSTRUCTED = 0x30
		return (BERTags.SEQUENCE | BERTags.CONSTRUCTED) == tagByte;
	}

	/**
	 * Reads the {@code encodable} and returns a {@code Date}
	 *
	 * @param encodable {@link ASN1Encodable} to read
	 * @return {@link Date}
	 */
	public static Date getDate(ASN1Encodable encodable) {
		try {
			return Time.getInstance(encodable).getDate();
		} catch (Exception e) {
			LOG.warn("Unable to retrieve the date {}", encodable, e);
			return null;
		}
	}

	/**
	 * Extracts all extended key usages for the certificate token
	 *
	 * @param certToken {@link CertificateToken}
	 * @return a list of {@link String}s
	 */
	public static List<String> getExtendedKeyUsage(CertificateToken certToken) {
		try {
			return certToken.getCertificate().getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			LOG.warn("Unable to retrieve ExtendedKeyUsage : {}", e.getMessage());
			return Collections.emptyList();
		}
	}

	/**
	 * Gets the {@code IssuerSerial} object
	 *
	 * @param binaries representing the {@link IssuerSerial}
	 * @return {@link IssuerSerial} if able to parse, null otherwise
	 */
	public static IssuerSerial getIssuerSerial(byte[] binaries) {
		try (ASN1InputStream is = new ASN1InputStream(binaries)) {
			ASN1Sequence seq = (ASN1Sequence) is.readObject();
			return IssuerSerial.getInstance(seq);
		} catch (Exception e) {
			LOG.warn("Unable to decode IssuerSerialV2 textContent '{}' : {}", Utils.toBase64(binaries), e.getMessage(), e);
			return null;
		}
	}

	/**
	 * Transforms an object of class {@code IssuerSerial} into instance of
	 * {@code CertificateIdentifier}
	 * 
	 * @param issuerAndSerial {@link IssuerSerial} to transform
	 * @return {@link SignerIdentifier}
	 */
	public static SignerIdentifier toSignerIdentifier(IssuerSerial issuerAndSerial) {
		if (issuerAndSerial == null) {
			return null;
		}
		try {
			SignerIdentifier signerIdentifier = new SignerIdentifier();
			GeneralNames gnames = issuerAndSerial.getIssuer();
			if (gnames != null) {
				GeneralName[] names = gnames.getNames();
				if (names.length == 1) {
					signerIdentifier.setIssuerName(new X500Principal(names[0].getName().toASN1Primitive().getEncoded(ASN1Encoding.DER)));
				} else {
					LOG.warn("More than one GeneralName");
				}
			}

			ASN1Integer serialNumber = issuerAndSerial.getSerial();
			if (serialNumber != null) {
				signerIdentifier.setSerialNumber(serialNumber.getValue());
			}

			return signerIdentifier;
		} catch (Exception e) {
			LOG.warn("Unable to read the IssuerSerial object", e);
			return null;
		}
	}
	
	/**
	 * Returns an array of {@link Attribute}s for a given {@code oid} found in the {@code attributeTable}
	 *
	 * @param attributeTable {@link AttributeTable}
	 * @param oid target {@link ASN1ObjectIdentifier}
	 * @return {@link Attribute}s array
	 */
	public static Attribute[] getAsn1Attributes(AttributeTable attributeTable, ASN1ObjectIdentifier oid) {
		ASN1EncodableVector encodableVector = attributeTable.getAll(oid);
		if (encodableVector == null) {
			return new Attribute[0];
		}
		Attributes attributes = new Attributes(encodableVector);
		return attributes.getAttributes();
	}
	
	/**
	 * Returns generation time for the provided {@code timeStampToken}
	 *
	 * @param timeStampToken {@link TimeStampToken} to get generation time for
	 * @return {@link Date} timestamp generation time
	 */
	public static Date getTimeStampTokenGenerationTime(TimeStampToken timeStampToken) {
		if (timeStampToken != null) {
			return timeStampToken.getTimeStampInfo().getGenTime();
		}
		return null;
	}

	/**
	 * Returns {@link RevocationValues} from the given encodable
	 * 
	 * @param encodable
	 *                  the encoded data to be parsed
	 * @return an instance of RevocationValues or null if the parsing failed
	 */
	public static RevocationValues getRevocationValues(ASN1Encodable encodable) {
		if (encodable != null) {
			try {
				return RevocationValues.getInstance(encodable);
			} catch (Exception e) {
				LOG.warn("Unable to parse RevocationValues", e);
			}
		}
		return null;
	}

	/**
	 * Converts the {@code OtherCertID} to {@code CertificateRef}
	 *
	 * @param otherCertId {@link OtherCertID}
	 * @return {@link CertificateRef}
	 */
	public static CertificateRef getCertificateRef(OtherCertID otherCertId) {
		CertificateRef certRef = new CertificateRef();
		DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(otherCertId.getAlgorithmHash().getAlgorithm().getId());
		certRef.setCertDigest(new Digest(digestAlgo, otherCertId.getCertHash()));
		certRef.setCertificateIdentifier(toSignerIdentifier(otherCertId.getIssuerSerial()));
		return certRef;
	}

	/**
	 * Checks if the binaries are ASN.1 encoded.
	 *
	 * @param binaries byte array to check.
	 * @return if the SignatureValue binaries are ASN.1 encoded.
	 */
	public static boolean isAsn1Encoded(byte[] binaries) {
		if (Utils.isArrayEmpty(binaries)) {
			return false;
		}
		try (ASN1InputStream is = new ASN1InputStream(binaries)) {
			return is.readObject() != null;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Checks if the SignatureValue binaries are ASN.1 encoded.
	 *
	 * @param binaries byte array to check.
	 * @return if the SignatureValue binaries are ASN.1 encoded.
	 */
	public static boolean isAsn1EncodedSignatureValue(byte[] binaries) {
		try (ASN1InputStream is = new ASN1InputStream(binaries)) {
			ASN1Sequence seq = (ASN1Sequence) is.readObject();
			return seq != null && seq.size() == 2;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Converts the ANS.1 binary signature value to the concatenated (plain) R || S format if required
	 * 
	 * NOTE: used in XAdES and JAdES
	 *
	 * @param algorithm
	 *            Encryption algorithm used to create the signatureValue
	 * @param signatureValue
	 *            the originally computed signature value
	 * @return the converted signature value
	 */
	public static byte[] ensurePlainSignatureValue(final EncryptionAlgorithm algorithm, byte[] signatureValue) {
		if ((EncryptionAlgorithm.ECDSA == algorithm || EncryptionAlgorithm.PLAIN_ECDSA == algorithm ||
				EncryptionAlgorithm.DSA == algorithm) && isAsn1EncodedSignatureValue(signatureValue)) {
			return toPlainDSASignatureValue(signatureValue);
		} else {
			return signatureValue;
		}
	}

	/**
	 * Converts an ASN.1 value to a concatenation string of R and S from ECDSA/DSA encryption algorithm
	 *
	 * The JAVA JCE ECDSA/DSA Signature algorithm creates ASN.1 encoded (r,s) value pairs.
	 *
	 * @param asn1SignatureValue
	 *            the ASN1 signature value
	 * @return the decoded bytes
	 * @see <a href="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</a>
	 * @see <a href="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</a>
	 */
	public static byte[] toPlainDSASignatureValue(byte[] asn1SignatureValue) {
		try {
			BigInteger order = getOrderFromSignatureValue(asn1SignatureValue);
			final BigInteger[] values = StandardDSAEncoding.INSTANCE.decode(order, asn1SignatureValue);
			return PlainDSAEncoding.INSTANCE.encode(order, values[0], values[1]);

		} catch (Exception e) {
			throw new DSSException("Unable to convert to plain : " + e.getMessage(), e);
		}
	}

	/**
	 * Converts a plain {@code signatureValue} to its corresponding ASN.1 format
	 *
	 * @param signatureValue
	 *            the plain signature value
	 * @return the encoded bytes
	 * @see <a href="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</a>
	 * @see <a href="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</a>
	 */
	public static byte[] toStandardDSASignatureValue(byte[] signatureValue) {
		try {
			BigInteger order = getOrderFromSignatureValue(signatureValue);
			final BigInteger[] values = PlainDSAEncoding.INSTANCE.decode(order, signatureValue);
			return StandardDSAEncoding.INSTANCE.encode(order, values[0], values[1]);

		} catch (Exception e) {
			throw new DSSException("Unable to convert to standard DSA : " + e.getMessage(), e);
		}
	}

	/**
	 * Gets the order parameter corresponding the given {@code signatureValue}
	 *
	 * @param signatureValue byte array
	 * @return {@link BigInteger}
	 */
	public static BigInteger getOrderFromSignatureValue(byte[] signatureValue) {
		try {
			BigInteger rValue;
			BigInteger sValue;
			if (DSSASN1Utils.isAsn1EncodedSignatureValue(signatureValue)) {
				ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(signatureValue);
				if (seq.size() != 2) {
					throw new IllegalArgumentException("ASN1 Sequence size should be 2!");
				}

				rValue = ((ASN1Integer) seq.getObjectAt(0)).getValue();
				sValue = ((ASN1Integer) seq.getObjectAt(1)).getValue();

			} else {
				if (signatureValue.length % 2 != 0) {
					throw new IllegalArgumentException("signatureValue binaries length shall be dividable by 2!");
				}
				int valueLength = signatureValue.length / 2;
				rValue = BigIntegers.fromUnsignedByteArray(signatureValue, 0, valueLength);
				sValue = BigIntegers.fromUnsignedByteArray(signatureValue, valueLength, valueLength);
			}

			BigInteger max = rValue.max(sValue);
			return max.add(BigInteger.ONE);

		} catch (IOException e) {
			throw new DSSException("Unable to extract order from a signature value : " + e.getMessage(), e);
		}
	}

	/**
	 * This method returns a bit length of the provided signature value
	 *
	 * @param signatureValue byte array representing the signature value
	 * @return bit length of the signature value
	 */
	public static int getSignatureValueBitLength(byte[] signatureValue) {
		try {
			BigInteger order = DSSASN1Utils.getOrderFromSignatureValue(signatureValue);
			return BigIntegers.getUnsignedByteLength(order) * 8; // convert to bits
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to extract a signature value bit length : %s", e.getMessage()), e);
		}
	}

	/**
	 * Returns a value of an ASN.1 DirectoryString instance Returns null if an error
	 * occurs during the transformation
	 * 
	 * @param directoryStringInstance {@link ASN1Encodable} to get DirectoryString
	 *                                value from
	 * @return {@link String} value
	 */
	public static String getDirectoryStringValue(ASN1Encodable directoryStringInstance) {
		String postalAddress = null;
		try {
			DirectoryString directoryString = DirectoryString.getInstance(directoryStringInstance);
			postalAddress = directoryString.getString();
		} catch (Exception e) {
			String errorMessage = "Unable to build a DirectoryString instance. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
		}
		return postalAddress;
	}

	/**
	 * Converts an object of {@code OCSPResponse} class to {@code BasicOCSPResp}
	 *
	 * @param ocspResponse {@link OCSPResponse} to convert
	 * @return {@link BasicOCSPResp}
	 * @throws OCSPException in case of a conversion error
	 */
	public static BasicOCSPResp toBasicOCSPResp(OCSPResponse ocspResponse) throws OCSPException {
		final OCSPResp ocspResp = new OCSPResp(ocspResponse);
		return (BasicOCSPResp) ocspResp.getResponseObject();
	}

	/**
	 * Converts an array of {@code OCSPResponse}s to an array of {@code BasicOCSPResp}s
	 *
	 * @param ocspResponses an array of {@link OCSPResponse}s to convert
	 * @return an array of {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp[] toBasicOCSPResps(OCSPResponse[] ocspResponses) {
		List<BasicOCSPResp> basicOCSPResps = new ArrayList<>();
		for (OCSPResponse ocspRespons : ocspResponses) {
			try {
				basicOCSPResps.add(toBasicOCSPResp(ocspRespons));
			} catch (OCSPException e) {
				LOG.warn("Error while converting OCSPResponse to BasicOCSPResp : {}", e.getMessage());
				return null;
			}
		}
		return basicOCSPResps.toArray(new BasicOCSPResp[0]);
	}

	/**
	 * Converts an array of {@code BasicOCSPResponse}s to an array of {@code BasicOCSPResp}s
	 *
	 * @param basicOCSPResponses an array of {@link BasicOCSPResponse}s to convert
	 * @return an array of {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp[] toBasicOCSPResps(BasicOCSPResponse[] basicOCSPResponses) {
		List<BasicOCSPResp> basicOCSPResps = new ArrayList<>();
		for (BasicOCSPResponse basicOCSPRespons : basicOCSPResponses) {
			basicOCSPResps.add(new BasicOCSPResp(basicOCSPRespons));
		}
		return basicOCSPResps.toArray(new BasicOCSPResp[0]);
	}

	/**
	 * Builds SPDocSpecification attribute from the given {@code oidOrUri}
	 *
	 * SPDocSpecification ::= CHOICE {
	 *  oid OBJECT IDENTIFIER,
	 *  uri IA5String
	 * }
	 *
	 * @param oidOrUri {@link String} represents OID or URI
	 * @return {@link ASN1Primitive}
	 */
	public static ASN1Primitive buildSPDocSpecificationId(String oidOrUri) {
		ASN1Primitive spDocSpecification;
		if (DSSUtils.isOidCode(oidOrUri)) {
			spDocSpecification = new ASN1ObjectIdentifier(oidOrUri);
		} else {
			spDocSpecification = new DERIA5String(oidOrUri);
		}
		return spDocSpecification;
	}

}
