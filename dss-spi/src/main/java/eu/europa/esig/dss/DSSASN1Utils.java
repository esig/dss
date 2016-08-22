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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERT61UTF8String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

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
	 * This method returns {@code T extends ASN1Primitive} created from array of bytes. The {@code IOException} is
	 * transformed in {@code DSSException}.
	 *
	 * @param bytes
	 *            array of bytes to be transformed to {@code ASN1Primitive}
	 * @return new {@code T extends ASN1Primitive}
	 */
	public static <T extends ASN1Primitive> T toASN1Primitive(final byte[] bytes) throws DSSException {
		try {
			@SuppressWarnings("unchecked")
			final T asn1Primitive = (T) ASN1Primitive.fromByteArray(bytes);
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
	private static boolean isDEROctetStringNull(final DEROctetString derOctetString) {
		final byte[] derOctetStringBytes = derOctetString.getOctets();
		final ASN1Primitive asn1Null = toASN1Primitive(derOctetStringBytes);
		return DERNull.INSTANCE.equals(asn1Null);
	}

	/**
	 * This method return DER encoded ASN1 attribute. The {@code IOException} is transformed in {@code DSSException}.
	 *
	 * @param asn1Encodable
	 *            asn1Encodable to be DER encoded
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
	 * Returns an ASN.1 encoded bytes representing the {@code TimeStampToken}
	 *
	 * @param timeStampToken
	 *            {@code TimeStampToken}
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
	 * This method returns the {@code ASN1Sequence} encapsulated in {@code DEROctetString}. The {@code DEROctetString}
	 * is represented as {@code byte} array.
	 *
	 * @param bytes
	 *            {@code byte} representation of {@code DEROctetString}
	 * @return encapsulated {@code ASN1Sequence}
	 * @throws DSSException
	 *             in case of a decoding problem
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
			Utils.closeQuietly(input);
		}
	}

	/**
	 * This method computes the digest of an ANS1 signature policy (used in CAdES)
	 *
	 * TS 101 733 5.8.1 : If the signature policy is defined using ASN.1, then the hash is calculated on the value
	 * without the outer type and length
	 * fields, and the hashing algorithm shall be as specified in the field sigPolicyHash.
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
	 * Gets the ASN.1 algorithm identifier structure corresponding to a signature algorithm
	 *
	 * @return the AlgorithmIdentifier
	 */
	public static AlgorithmIdentifier getAlgorithmIdentifier(SignatureAlgorithm signatureAlgorithm) {
		final String jceId = signatureAlgorithm.getJCEId();
		final ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(jceId);
		final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(asn1ObjectIdentifier, DERNull.INSTANCE);
		return algorithmIdentifier;
	}

	/**
	 * Gets the ASN.1 algorithm identifier structure corresponding to a digest algorithm
	 *
	 * @return the AlgorithmIdentifier
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
		final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(asn1ObjectIdentifier, DERNull.INSTANCE);
		return algorithmIdentifier;
	}

	/**
	 * Indicates if the revocation data should be checked for an OCSP signing certificate.<br>
	 * http://www.ietf.org/rfc/rfc2560.txt?number=2560<br>
	 * A CA may specify that an OCSP client can trust a responder for the lifetime of the responder's certificate. The
	 * CA
	 * does so by including the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical extension. The value of
	 * the
	 * extension should be NULL.
	 *
	 * @return
	 */
	public static boolean hasIdPkixOcspNoCheckExtension(CertificateToken token) {
		final byte[] extensionValue = token.getCertificate().getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
		if (extensionValue != null) {
			try {
				final ASN1Primitive derObject = toASN1Primitive(extensionValue);
				if (derObject instanceof DEROctetString) {
					return isDEROctetStringNull((DEROctetString) derObject);
				}
			} catch (Exception e) {
				LOG.debug("Exception when processing 'id_pkix_ocsp_no_check'", e);
			}
		}
		return false;
	}

	public static List<String> getPolicyIdentifiers(final CertificateToken certToken) {
		List<String> policyIdentifiers = new ArrayList<String>();
		final byte[] certificatePolicies = certToken.getCertificate().getExtensionValue(Extension.certificatePolicies.getId());
		if (certificatePolicies != null) {
			ASN1Sequence seq = getAsn1SequenceFromDerOctetString(certificatePolicies);
			for (int ii = 0; ii < seq.size(); ii++) {
				final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
				policyIdentifiers.add(policyInfo.getPolicyIdentifier().getId());
			}
		}
		return policyIdentifiers;
	}

	/**
	 * Get the OIDs of the QCStatements extension of the certificate.
	 * @param certToken
	 * @return list of OIDs: empty list if no QCStatements extension found
	 */
	public static List<String> getQCStatementsIdList(final CertificateToken certToken) {
		final List<String> extensionIdList = new ArrayList<String>();
		for (final QCStatement qcStatement : getQCStatementsList(certToken)) {
			extensionIdList.add(qcStatement.getStatementId().getId());
		}
		return extensionIdList;
	}

	/**
	 * Get the contents of the QCStatements extension of the certificate.
	 * @param certToken
	 * @return list of OIDs: empty list if no QCStatements extension found
	 */
	public static List<QCStatement> getQCStatementsList(final CertificateToken certToken) {
		final List<QCStatement> extensionList = new ArrayList<QCStatement>();
		final byte[] qcStatement = certToken.getCertificate().getExtensionValue(Extension.qCStatements.getId());
		if (qcStatement != null) {
			final ASN1Sequence seq = getAsn1SequenceFromDerOctetString(qcStatement);
			// Sequence of QCStatement
			for (final Object item : seq) {
				final QCStatement statement = QCStatement.getInstance(item);
				extensionList.add(statement);
			}
		}
		return extensionList;
	}

	/**
	 * This method returns SKI bytes from the certificate extension.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken}
	 * @return ski bytes from the given certificate or null if missing
	 * @throws DSSException
	 */
	public static byte[] getSki(final CertificateToken certificateToken) throws DSSException {
		return getSki(certificateToken, false);
	}

	/**
	 * This method returns SKI bytes from certificate.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken}
	 * @param computeIfMissing
	 *            if the extension is missing and computeIfMissing = true, it will compute the SKI value from the Public
	 *            Key
	 * @return ski bytes from the given certificate
	 * @throws DSSException
	 */
	public static byte[] getSki(final CertificateToken certificateToken, boolean computeIfMissing) throws DSSException {
		try {
			byte[] sKI = certificateToken.getCertificate().getExtensionValue(Extension.subjectKeyIdentifier.getId());
			if (Utils.isArrayNotEmpty(sKI)) {
				ASN1Primitive extension = X509ExtensionUtil.fromExtensionValue(sKI);
				SubjectKeyIdentifier skiBC = SubjectKeyIdentifier.getInstance(extension);
				return skiBC.getKeyIdentifier();
			} else if (computeIfMissing) {
				// If extension not present, we compute it from the certificate public key
				DLSequence seq = (DLSequence) DERSequence.fromByteArray(certificateToken.getPublicKey().getEncoded());
				DERBitString item = (DERBitString) seq.getObjectAt(1);
				return DSSUtils.digest(DigestAlgorithm.SHA1, item.getOctets());
			}
			return null;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public static List<String> getAccessLocations(final CertificateToken certificate) {
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
	 * Indicates that a X509Certificates corresponding private key is used by an authority to sign OCSP-Responses.<br>
	 * http://www.ietf.org/rfc/rfc3280.txt <br>
	 * http://tools.ietf.org/pdf/rfc6960.pdf 4.2.2.2<br>
	 * {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) keyPurpose(3)
	 * ocspSigning(9)}<br>
	 * OID: 1.3.6.1.5.5.7.3.9
	 *
	 * @return
	 */
	public static boolean isOCSPSigning(CertificateToken certToken) {
		try {
			List<String> keyPurposes = certToken.getCertificate().getExtendedKeyUsage();
			if ((keyPurposes != null) && keyPurposes.contains(OID.id_kp_OCSPSigning.getId())) {
				return true;
			}
		} catch (CertificateParsingException e) {
			LOG.warn(e.getMessage());
		}
		// Responder's certificate not valid for signing OCSP responses.
		return false;
	}

	/**
	 * Returns a {@code X509CertificateHolder} encapsulating the given {@code X509Certificate}.
	 *
	 * @return a X509CertificateHolder holding this certificate
	 */
	public static X509CertificateHolder getX509CertificateHolder(CertificateToken certToken) {
		try {
			return new X509CertificateHolder(certToken.getEncoded());
		} catch (IOException e) {
			throw new DSSException(e);
		}
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
		final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);
		return issuerSerial;
	}

	public static Map<String, String> get(final X500Principal x500Principal) {
		Map<String, String> treeMap = new HashMap<String, String>();
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

	public static String getUtf8String(final X500Principal x500Principal) {

		final byte[] encoded = x500Principal.getEncoded();
		final ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(encoded);
		final ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
		final StringBuilder stringBuilder = new StringBuilder();
		/**
		 * RFC 4514 LDAP: Distinguished Names
		 * 2.1. Converting the RDNSequence
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
				 * RFC 4514 LDAP: Distinguished Names
				 * ...
				 * Other characters may be escaped.
				 *
				 * Each octet of the character to be escaped is replaced by a backslash
				 * and two hex digits, which form a single octet in the code of the
				 * character. Alternatively, if and only if the character to be escaped
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
				// attributeValue.getClass().getSimpleName() + "[" + string + "]");
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
			LOG.error("!!!*******!!! This encoding is unknown: " + attributeValue.getClass().getSimpleName());
			string = attributeValue.toString();
			LOG.error("!!!*******!!! value: " + string);
		}
		return string;
	}

	public static String extractAttributeFromX500Principal(ASN1ObjectIdentifier identifier, X500Principal X500PrincipalName) {
		final X500Name x500Name = X500Name.getInstance(X500PrincipalName.getEncoded());
		RDN[] rdns = x500Name.getRDNs(identifier);
		if (rdns.length > 0) {
			return rdns[0].getFirst().getValue().toString();
		}
		return null;
	}

	public static Date getExpiredCertsOnCRL(X509CRL x509crl) {
		Set<String> nonCriticalExtensionOIDs = x509crl.getNonCriticalExtensionOIDs();
		if ((nonCriticalExtensionOIDs != null) && nonCriticalExtensionOIDs.contains(OID.id_ce_expiredCertsOnCRL.getId())) {
			byte[] extensionValue = x509crl.getExtensionValue(OID.id_ce_expiredCertsOnCRL.getId());
			if (Utils.isArrayNotEmpty(extensionValue)) {
				try {
					ASN1OctetString octetString = (ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue);
					ASN1GeneralizedTime generalTime = (ASN1GeneralizedTime) ASN1Primitive.fromByteArray(octetString.getOctets());
					return generalTime.getDate();
				} catch (Exception e) {
					LOG.error("Unable to retrieve id_ce_expiredCertsOnCRL on CRL : " + e.getMessage(), e);
				}
			}
		}
		return null;
	}

}