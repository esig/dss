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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class that contains some ASN1 related method.
 *
 */
public final class DSSASN1Utils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSASN1Utils.class);

	/**
	 * This class is an utility class and cannot be instantiated.
	 */
	private DSSASN1Utils() {

	}

	/**
	 * This method returns {@code T extends ASN1Primitive} created from array of bytes. The {@code IOException} is transformed in {@code DSSException}.
	 *
	 * @param bytes array of bytes to be transformed to {@code ASN1Primitive}
	 * @return new {@code T extends ASN1Primitive}
	 */
	public static <T extends ASN1Primitive> T toASN1Primitive(final byte[] bytes) throws DSSException {

		try {
			@SuppressWarnings("unchecked") final T asn1Primitive = (T) ASN1Primitive.fromByteArray(bytes);
			return asn1Primitive;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method checks if a given {@code DEROctetString} is null.
	 *
	 * @param derOctetString
	 * @return
	 */
	public static boolean isDEROctetStringNull(final DEROctetString derOctetString) {

		final byte[] derOctetStringBytes = derOctetString.getOctets();
		final ASN1Primitive asn1Null = DSSASN1Utils.toASN1Primitive(derOctetStringBytes);
		return DERNull.INSTANCE.equals(asn1Null);
	}

	/**
	 * This method return DER encoded ASN1 attribute. The {@code IOException} is transformed in {@code DSSException}.
	 *
	 * @param asn1Encodable asn1Encodable to be DER encoded
	 * @return array of bytes representing the DER encoded asn1Encodable
	 */
	public static byte[] getDEREncoded(ASN1Encodable asn1Encodable) {
		try {
			return asn1Encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] getEncoded(BasicOCSPResp basicOCSPResp) {
		try {
			BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(basicOCSPResp.getEncoded());
			return getDEREncoded(basicOCSPResponse);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method return {@code X509Certificate} representing {@code X509CertificateHolder}. The {@code CertificateParsingException} is transformed in {@code
	 * DSSException}.
	 *
	 * @param certificateHolder {@code X509CertificateHolder}
	 * @return {@code X509Certificate}.
	 * @throws DSSException
	 */
	public static X509Certificate getCertificate(final X509CertificateHolder certificateHolder) throws DSSException {

		try {

			final X509Certificate certificate = new X509CertificateObject(certificateHolder.toASN1Structure());
			return certificate;
		} catch (CertificateParsingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns DER encoded array of bytes representing {@code X509Certificate} for given {@code X509CertificateHolder}. The {@code
	 * IOException} is transformed in {@code DSSException}.
	 *
	 * @param certificateHolder {@code X509CertificateHolder}
	 * @return DER encoded array of bytes representing {@code X509Certificate}.
	 * @throws DSSException
	 */
	public static byte[] getCertificateDEREncoded(final X509CertificateHolder certificateHolder) throws DSSException {

		try {

			final byte[] bytes = certificateHolder.getEncoded();
			return bytes;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static Date toDate(final ASN1UTCTime asn1Date) throws DSSException {
		try {
			return asn1Date.getDate();
		} catch (ParseException e) {
			throw new DSSException(e);
		}
	}

	public static Date toDate(final ASN1GeneralizedTime asn1Date) throws DSSException {
		try {
			return asn1Date.getDate();
		} catch (ParseException e) {
			throw new DSSException(e);
		}
	}

	public static String toString(final ASN1OctetString value) {

		return new String(value.getOctets());
	}

	/**
	 * Returns the ASN.1 encoded representation of {@code CMSSignedData}.
	 *
	 * @param data
	 * @return
	 * @throws DSSException
	 */
	public static byte[] getEncoded(final CMSSignedData data) throws DSSException {

		try {
			return data.getEncoded();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method generate {@code CMSSignedData} using the provided #{@code CMSSignedDataGenerator}, the content and the indication if the content should be encapsulated.
	 *
	 * @param generator
	 * @param content
	 * @param encapsulate
	 * @return
	 * @throws DSSException
	 */
	public static CMSSignedData generateCMSSignedData(final CMSSignedDataGenerator generator, final CMSProcessableByteArray content,
			final boolean encapsulate) throws DSSException {

		try {
			final CMSSignedData cmsSignedData = generator.generate(content, encapsulate);
			return cmsSignedData;
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}

	public static CMSSignedData generateDetachedCMSSignedData(final CMSSignedDataGenerator generator, final CMSProcessableByteArray content) throws DSSException {
		return generateCMSSignedData(generator, content, false);
	}

	/**
	 * Returns an ASN.1 encoded bytes representing the {@code TimeStampToken}
	 *
	 * @param timeStampToken {@code TimeStampToken}
	 * @return Returns an ASN.1 encoded bytes representing the {@code TimeStampToken}
	 */
	public static byte[] getEncoded(final TimeStampToken timeStampToken) throws DSSException {

		try {
			final byte[] encoded = timeStampToken.getEncoded();
			return encoded;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method generates a bouncycastle {@code TimeStampToken} based on base 64 encoded {@code String}.
	 *
	 * @param base64EncodedTimestamp
	 * @return bouncycastle {@code TimeStampToken}
	 * @throws DSSException
	 */
	public static TimeStampToken createTimeStampToken(final String base64EncodedTimestamp) throws DSSException {
		try {
			final byte[] tokenBytes = Base64.decodeBase64(base64EncodedTimestamp);
			final CMSSignedData signedData = new CMSSignedData(tokenBytes);
			return new TimeStampToken(signedData);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method allows to create a {@code BasicOCSPResp} from a {@code DERSequence}.
	 *
	 * @param otherRevocationInfoMatch {@code DERSequence} to convert to {@code BasicOCSPResp}
	 * @return {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp getBasicOcspResp(final DERSequence otherRevocationInfoMatch) {

		BasicOCSPResp basicOCSPResp = null;
		try {
			final BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(otherRevocationInfoMatch);
			basicOCSPResp = new BasicOCSPResp(basicOcspResponse);
		} catch (Exception e) {
			LOG.error("Impossible to create BasicOCSPResp from DERSequence!", e);
		}
		return basicOCSPResp;
	}

	/**
	 * This method allows to create a {@code OCSPResp} from a {@code DERSequence}.
	 *
	 * @param otherRevocationInfoMatch {@code DERSequence} to convert to {@code OCSPResp}
	 * @return {@code OCSPResp}
	 */
	public static OCSPResp getOcspResp(final DERSequence otherRevocationInfoMatch) {

		OCSPResp ocspResp = null;
		try {
			final OCSPResponse ocspResponse = OCSPResponse.getInstance(otherRevocationInfoMatch);
			ocspResp = new OCSPResp(ocspResponse);
		} catch (Exception e) {
			LOG.error("Impossible to create OCSPResp from DERSequence!", e);
		}
		return ocspResp;
	}

	/**
	 * This method returns the {@code BasicOCSPResp} from a {@code OCSPResp}.
	 *
	 * @param ocspResp {@code OCSPResp} to analysed
	 * @return
	 */
	public static BasicOCSPResp getBasicOCSPResp(final OCSPResp ocspResp) {

		BasicOCSPResp basicOCSPResp = null;
		try {
			final Object responseObject = ocspResp.getResponseObject();
			if (responseObject instanceof BasicOCSPResp) {

				basicOCSPResp = (BasicOCSPResp) responseObject;
			} else {
				LOG.warn("Unknown OCSP response type: {}", responseObject.getClass());
			}
		} catch (OCSPException e) {
			LOG.error("Impossible to process OCSPResp!", e);
		}
		return basicOCSPResp;
	}

	/**
	 * This method returns the {@code ASN1Sequence} encapsulated in {@code DEROctetString}. The {@code DEROctetString} is represented as {@code byte} array.
	 *
	 * @param bytes {@code byte} representation of {@code DEROctetString}
	 * @return encapsulated {@code ASN1Sequence}
	 * @throws DSSException in case of a decoding problem
	 */
	public static ASN1Sequence getAsn1SequenceFromDerOctetString(byte[] bytes) throws DSSException {

		ASN1InputStream input = null;
		try {

			input = new ASN1InputStream(bytes);
			final DEROctetString s = (DEROctetString) input.readObject();
			final byte[] content = s.getOctets();
			input.close();
			input = new ASN1InputStream(content);
			final ASN1Sequence seq = (ASN1Sequence) input.readObject();
			return seq;
		} catch (IOException e) {
			throw new DSSException("Error when computing certificate's extensions.", e);
		} finally {
			IOUtils.closeQuietly(input);
		}
	}

	/**
	 * @param signerInformation {@code SignerInformation}
	 * @return {@code DERTaggedObject} representing the signed attributes
	 * @throws DSSException in case of a decoding problem
	 */
	public static DERTaggedObject getDERSignedAttributes(final SignerInformation signerInformation) throws DSSException {

		try {
			final byte[] encodedSignedAttributes = signerInformation.getEncodedSignedAttributes();
			if (encodedSignedAttributes == null) {
				return null;
			}
			final ASN1Set asn1Set = DSSASN1Utils.toASN1Primitive(encodedSignedAttributes);
			return new DERTaggedObject(false, 0, asn1Set);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method computes the digest of an ANS1 signature policy (used in CAdES)
	 *
	 * TS 101 733 5.8.1 : If the signature policy is defined using ASN.1, then the hash is calculated on the value without the outer type and length
	 * fields, and the hashing algorithm shall be as specified in the field sigPolicyHash.
	 */
	public static byte[] getAsn1SignaturePolicyDigest(DigestAlgorithm digestAlgorithm, byte[] policyBytes) {
		ASN1Sequence asn1Seq = DSSASN1Utils.toASN1Primitive(policyBytes);

		ASN1Sequence signPolicyHashAlgObject = (ASN1Sequence) asn1Seq.getObjectAt(0);
		AlgorithmIdentifier signPolicyHashAlgIdentifier = AlgorithmIdentifier.getInstance(signPolicyHashAlgObject);
		ASN1Sequence signPolicyInfo = (ASN1Sequence) asn1Seq.getObjectAt(1);

		byte[] hashAlgorithmDEREncoded = getDEREncoded(signPolicyHashAlgIdentifier);
		byte[] signPolicyInfoDEREncoded = getDEREncoded(signPolicyInfo);
		return DSSUtils.digest(digestAlgorithm, hashAlgorithmDEREncoded, signPolicyInfoDEREncoded);
	}

	/**
	 * This method can be removed the simple IssuerSerial verification can be
	 * performed. In fact the hash verification is sufficient.
	 *
	 * @param generalNames
	 * @return
	 */
	public static String getCanonicalizedName(final GeneralNames generalNames) {
		GeneralName[] names = generalNames.getNames();
		TreeMap<String, String> treeMap = new TreeMap<String, String>();
		for (GeneralName name : names) {
			String ldapString = String.valueOf(name.getName());
			LOG.debug("ldapString to canonicalize: {} ", ldapString);
			try {
				LdapName ldapName = new LdapName(ldapString);
				List<Rdn> rdns = ldapName.getRdns();
				for (final Rdn rdn : rdns) {
					treeMap.put(rdn.getType().toLowerCase(), String.valueOf(rdn.getValue()).toLowerCase());
				}
			} catch (InvalidNameException e) {
				throw new DSSException(e);
			}
		}
		StringBuilder stringBuilder = new StringBuilder();
		for (Entry<String, String> entry : treeMap.entrySet()) {
			stringBuilder.append(entry.getKey()).append('=').append(entry.getValue()).append('|');
		}
		final String canonicalizedName = stringBuilder.toString();
		LOG.debug("canonicalizedName: {} ", canonicalizedName);
		return canonicalizedName;
	}

	/**
	 * This method returns the signed content extracted from a CMSTypedData
	 * @param cmsTypedData
	 *            {@code CMSTypedData} cannot be null
	 * @return the signed content extracted from {@code CMSTypedData}
	 */
	public static byte[] getSignedContent(final CMSTypedData cmsTypedData) {
		try {
			final ByteArrayOutputStream originalDocumentData = new ByteArrayOutputStream();
			cmsTypedData.write(originalDocumentData);
			return originalDocumentData.toByteArray();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the existing unsigned attributes or a new empty attributes hashtable
	 *
	 * @param signerInformation
	 *            the signer information
	 * @return the existing unsigned attributes or an empty attributes hashtable
	 */
	public static AttributeTable getUnsignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		if (unsignedAttributes == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return unsignedAttributes;
		}
	}

	/**
	 * This method returns the existing signed attributes or a new empty attributes hashtable
	 *
	 * @param signerInformation
	 *            the signer information
	 * @return the existing signed attributes or an empty attributes {@code Hashtable}
	 */
	public static AttributeTable getSignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		if (signedAttributes == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return signedAttributes;
		}
	}

}