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
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
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

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	private static final String QC_TYPE_STATEMENT_OID = "0.4.0.1862.1.6";

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
	 * @param <T>
	 *            the expected return type
	 * @return new {@code T extends ASN1Primitive}
	 */
	@SuppressWarnings("unchecked")
	public static <T extends ASN1Primitive> T toASN1Primitive(final byte[] bytes) {
		try {
			return (T) ASN1Primitive.fromByteArray(bytes);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method checks if a given {@code DEROctetString} is null.
	 *
	 * @param derOctetString
	 *            the {@code DEROctetString} to check
	 * @return true if the {@code DEROctetString} contains DERNull
	 */
	private static boolean isDEROctetStringNull(final DEROctetString derOctetString) {
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
			throw new DSSException("Unable to encode to " + encoding, e);
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

	public static Date toDate(final ASN1GeneralizedTime asn1Date) {
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
	 *                       {@code TimeStampToken}
	 * @return the binary of the {@code TimeStampToken} @ if the {@code
	 * TimeStampToken} encoding fails
	 */
	public static byte[] getEncoded(final TimeStampToken timeStampToken) {
		try {
			return timeStampToken.getEncoded();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the {@code ASN1Sequence} encapsulated in
	 * {@code DEROctetString}. The {@code DEROctetString} is represented as
	 * {@code byte} array.
	 *
	 * @param bytes
	 *              {@code byte} representation of {@code DEROctetString}
	 * @return encapsulated {@code ASN1Sequence} @ in case of a decoding problem
	 */
	public static ASN1Sequence getAsn1SequenceFromDerOctetString(byte[] bytes) {
		return getASN1Sequence(getDEROctetStringContent(bytes));
	}

	private static byte[] getDEROctetStringContent(byte[] bytes) {
		try (ASN1InputStream input = new ASN1InputStream(bytes)) {
			final DEROctetString s = (DEROctetString) input.readObject();
			return s.getOctets();
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the DEROctetString content", e);
		}
	}

	private static ASN1Sequence getASN1Sequence(byte[] bytes) {
		try (ASN1InputStream input = new ASN1InputStream(bytes)) {
			return (ASN1Sequence) input.readObject();
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the ASN1Sequence", e);
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
	 * This method can be removed the simple IssuerSerial verification can be
	 * performed. In fact the hash verification is sufficient.
	 *
	 * @param generalNames
	 *            the generalNames
	 * @return the canonicalized name
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
	 * Indicates if the revocation data should be checked for an OCSP signing certificate.<br>
	 * http://www.ietf.org/rfc/rfc2560.txt?number=2560<br>
	 * A CA may specify that an OCSP client can trust a responder for the lifetime of the responder's certificate. The
	 * CA does so by including the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical extension. The value of
	 * the extension should be NULL.
	 *
	 * @param token
	 *            the certificate to be checked
	 * @return true if the certificate has the id_pkix_ocsp_nocheck extension
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

	public static List<CertificatePolicy> getCertificatePolicies(final CertificateToken certToken) {
		List<CertificatePolicy> certificatePolicies = new ArrayList<CertificatePolicy>();
		final byte[] certificatePoliciesBinaries = certToken.getCertificate().getExtensionValue(Extension.certificatePolicies.getId());
		if (Utils.isArrayNotEmpty(certificatePoliciesBinaries)) {
			try {
				ASN1Sequence seq = getAsn1SequenceFromDerOctetString(certificatePoliciesBinaries);
				for (int ii = 0; ii < seq.size(); ii++) {
					CertificatePolicy cp = new CertificatePolicy();
					final PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(ii));
					cp.setOid(policyInfo.getPolicyIdentifier().getId());
					ASN1Sequence policyQualifiersSeq = policyInfo.getPolicyQualifiers();
					if (policyQualifiersSeq != null) {
						for (int jj = 0; jj < policyQualifiersSeq.size(); jj++) {
							PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(policyQualifiersSeq.getObjectAt(jj));
							if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
								cp.setCpsUrl(getString(pqi.getQualifier()));
							}
						}
					}
					certificatePolicies.add(cp);
				}
			} catch (Exception e) {
				LOG.warn("Unable to parse the certificatePolicies extension '" + Utils.toBase64(certificatePoliciesBinaries) + "' : " + e.getMessage(), e);
			}
		}
		return certificatePolicies;
	}

	/**
	 * Get the list of all QCStatement Ids that are present in the certificate.
	 * (As per ETSI EN 319 412-5 V2.1.1)
	 * 
	 * @param certToken
	 *            the certificate
	 * @return the list of QC Statements oids
	 */
	public static List<String> getQCStatementsIdList(final CertificateToken certToken) {
		final List<String> extensionIdList = new ArrayList<String>();
		final byte[] qcStatement = certToken.getCertificate().getExtensionValue(Extension.qCStatements.getId());
		if (Utils.isArrayNotEmpty(qcStatement)) {
			try {
				final ASN1Sequence seq = getAsn1SequenceFromDerOctetString(qcStatement);
				// Sequence of QCStatement
				for (int ii = 0; ii < seq.size(); ii++) {
					final QCStatement statement = QCStatement.getInstance(seq.getObjectAt(ii));
					extensionIdList.add(statement.getStatementId().getId());
				}
			} catch (Exception e) {
				LOG.warn("Unable to parse the qCStatements extension '" + Utils.toBase64(qcStatement) + "' : " + e.getMessage(), e);
			}
		}
		return extensionIdList;
	}

	/**
	 * Get the list of all QCType Ids that are present in the certificate.
	 * (As per ETSI EN 319 412-5 V2.1.1)
	 * 
	 * @param certToken
	 *            the certificate
	 * @return the list of QCTypes oids
	 */
	public static List<String> getQCTypesIdList(final CertificateToken certToken) {
		final List<String> qcTypesIdList = new ArrayList<String>();
		final byte[] qcStatement = certToken.getCertificate().getExtensionValue(Extension.qCStatements.getId());
		if (Utils.isArrayNotEmpty(qcStatement)) {
			try {
				final ASN1Sequence seq = getAsn1SequenceFromDerOctetString(qcStatement);
				// Sequence of QCStatement
				for (int ii = 0; ii < seq.size(); ii++) {
					final QCStatement statement = QCStatement.getInstance(seq.getObjectAt(ii));
					if (QC_TYPE_STATEMENT_OID.equals(statement.getStatementId().getId())) {
						final ASN1Encodable qcTypeInfo1 = statement.getStatementInfo();
						if (qcTypeInfo1 instanceof ASN1Sequence) {
							final ASN1Sequence qcTypeInfo = (ASN1Sequence) qcTypeInfo1;
							for (int jj = 0; jj < qcTypeInfo.size(); jj++) {
								final ASN1Encodable e1 = qcTypeInfo.getObjectAt(jj);
								if (e1 instanceof ASN1ObjectIdentifier) {
									final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e1;
									qcTypesIdList.add(oid.getId());
								} else {
									LOG.warn("ASN1Sequence in QcTypes does not contain ASN1ObjectIdentifer, but {}",
											e1.getClass().getName());
								}
							}
						} else {
							LOG.warn("QcTypes not an ASN1Sequence, but {}", qcTypeInfo1.getClass().getName());
						}
					}
				}
			} catch (Exception e) {
				LOG.warn("Unable to parse the qCStatements extension '" + Utils.toBase64(qcStatement) + "' : " + e.getMessage(), e);
			}
		}

		return qcTypesIdList;
	}

	/**
	 * This method returns the Subject Key Identifier (SKI) bytes from the
	 * certificate extension (SHA-1 of the public key of the current certificate).
	 *
	 * @param certificateToken
	 *                         the {@code CertificateToken}
	 * @return ski bytes from the given certificate or null if missing
	 */
	public static byte[] getSki(final CertificateToken certificateToken) {
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
	 */
	public static byte[] getSki(final CertificateToken certificateToken, boolean computeIfMissing) {
		try {
			byte[] extensionValue = certificateToken.getCertificate().getExtensionValue(Extension.subjectKeyIdentifier.getId());
			if (Utils.isArrayNotEmpty(extensionValue)) {
				ASN1Primitive extension = JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
				SubjectKeyIdentifier skiBC = SubjectKeyIdentifier.getInstance(extension);
				return skiBC.getKeyIdentifier();
			} else if (computeIfMissing) {
				// If extension not present, we compute it from the certificate public key
				return computeSkiFromCert(certificateToken);
			}
			return null;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns authority key identifier as binaries from the certificate
	 * extension (SHA-1 of the public key of the issuer certificate).
	 *
	 * @param certificateToken
	 *                         the {@code CertificateToken}
	 * @return authority key identifier bytes from the given certificate (can be
	 *         null if the certificate is self signed)
	 */
	public static byte[] getAuthorityKeyIdentifier(CertificateToken certificateToken) {
		byte[] extensionValue = certificateToken.getCertificate().getExtensionValue(Extension.authorityKeyIdentifier.getId());
		if (Utils.isArrayNotEmpty(extensionValue)) {
			try {
				ASN1Primitive extension = JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
				AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extension);
				return aki.getKeyIdentifier();
			} catch (IOException e) {
				throw new DSSException("Unable to parse the authorityKeyIdentifier extension", e);
			}
		}
		return null;
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
			DLSequence seq = (DLSequence) DERSequence.fromByteArray(publicKey.getEncoded());
			DERBitString item = (DERBitString) seq.getObjectAt(1);
			return DSSUtils.digest(DigestAlgorithm.SHA1, item.getOctets());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Gives back the CA URIs meta-data found within the given certificate.
	 *
	 * @param certificate
	 *            the certificate token.
	 * @return a list of CA URIs, or empty list if the extension is not present.
	 */
	public static List<String> getCAAccessLocations(final CertificateToken certificate) {
		return getAccessLocations(certificate, X509ObjectIdentifiers.id_ad_caIssuers);
	}

	/**
	 * Gives back the OCSP URIs meta-data found within the given X509 cert.
	 *
	 * @param certificate
	 *            the cert token.
	 * @return a list of OCSP URIs, or empty list if the extension is not present.
	 */
	public static List<String> getOCSPAccessLocations(final CertificateToken certificate) {
		return getAccessLocations(certificate, X509ObjectIdentifiers.id_ad_ocsp);
	}

	private static List<String> getAccessLocations(final CertificateToken certificate, ASN1ObjectIdentifier aiaType) {
		List<String> locationsUrls = new ArrayList<String>();
		final byte[] authInfoAccessExtensionValue = certificate.getCertificate().getExtensionValue(Extension.authorityInfoAccess.getId());
		if (null == authInfoAccessExtensionValue) {
			return locationsUrls;
		}

		try {
			ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(authInfoAccessExtensionValue);
			AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(asn1Sequence);
			AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
			for (AccessDescription accessDescription : accessDescriptions) {
				if (aiaType.equals(accessDescription.getAccessMethod())) {
					GeneralName gn = accessDescription.getAccessLocation();
					String location = parseGn(gn);
					if (location != null) {
						locationsUrls.add(location);
					}
				}
			}
		} catch (Exception e) {
			LOG.error("Unable to parse authorityInfoAccess", e);
		}
		return locationsUrls;
	}

	/**
	 * Gives back the {@code List} of CRL URI meta-data found within the given X509 certificate.
	 *
	 * @param certificateToken
	 *            the cert token certificate
	 * @return the {@code List} of CRL URI, or empty list if the extension is not present
	 */
	public static List<String> getCrlUrls(final CertificateToken certificateToken) {
		final List<String> urls = new ArrayList<String>();

		final byte[] crlDistributionPointsBytes = certificateToken.getCertificate().getExtensionValue(Extension.cRLDistributionPoints.getId());
		if (crlDistributionPointsBytes != null) {
			try {
				final ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(crlDistributionPointsBytes);
				final CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Sequence);
				final DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
				for (final DistributionPoint distributionPoint : distributionPoints) {

					final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
					if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {
						continue;
					}
					final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
					final GeneralName[] names = generalNames.getNames();
					for (final GeneralName name : names) {
						String location = parseGn(name);
						if (location != null) {
							urls.add(location);
						}
					}
				}
			} catch (Exception e) {
				LOG.error("Unable to parse cRLDistributionPoints", e);
			}
		}

		return urls;
	}

	private static String parseGn(GeneralName gn) {
		try {
			if (GeneralName.uniformResourceIdentifier == gn.getTagNo()) {
				ASN1String str = (ASN1String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
				return str.getString();
			}
		} catch (Exception e) {
			LOG.warn("Unable to parse GN " + gn, e);
		}
		return null;
	}

	/**
	 * Indicates that a X509Certificates corresponding private key is used by an authority to sign OCSP-Responses.<br>
	 * http://www.ietf.org/rfc/rfc3280.txt <br>
	 * http://tools.ietf.org/pdf/rfc6960.pdf 4.2.2.2<br>
	 * {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) keyPurpose(3)
	 * ocspSigning(9)}<br>
	 * OID: 1.3.6.1.5.5.7.3.9
	 *
	 * @param certToken
	 *            the certificate token
	 * @return true if the certificate has the id_kp_OCSPSigning ExtendedKeyUsage
	 */
	public static boolean isOCSPSigning(CertificateToken certToken) {
		return isExtendedKeyUsagePresent(certToken, KeyPurposeId.id_kp_OCSPSigning.toOID());
	}

	public static boolean isExtendedKeyUsagePresent(CertificateToken certToken, ASN1ObjectIdentifier oid) {
		try {
			List<String> keyPurposes = certToken.getCertificate().getExtendedKeyUsage();
			if ((keyPurposes != null) && keyPurposes.contains(oid.getId())) {
				return true;
			}
		} catch (CertificateParsingException e) {
			LOG.error("Unable to retrieve ExtendedKeyUsage from certificate", e);
		}
		return false;
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
			throw new DSSException(e);
		}
	}

	public static CertificateToken getCertificate(final X509CertificateHolder x509CertificateHolder) {
		try {
			JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(DSSSecurityProvider.getSecurityProviderName());
			X509Certificate x509Certificate = converter.getCertificate(x509CertificateHolder);
			return new CertificateToken(x509Certificate);
		} catch (CertificateException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns a new IssuerSerial based on x500Principal of issuer and serial number
	 *
	 * @param issuerX500Principal
	 *            the {@link X500Principal} of certificate token's issuer
	 * @param serialNumber
	 *            serial number of certificate token
	 * @return a IssuerSerial
	 */
	public static IssuerSerial getIssuerSerial(final X500Principal issuerX500Principal, BigInteger serialNumber) {
		final X500Name issuerX500Name = X500Name.getInstance(issuerX500Principal.getEncoded());
		final GeneralName generalName = new GeneralName(issuerX500Name);
		final GeneralNames generalNames = new GeneralNames(generalName);
		return new IssuerSerial(generalNames, serialNumber);
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
				 */
				string = Rdn.escapeValue(string);
				if (stringBuilder.length() != 0) {
					stringBuilder.append(',');
				}
				stringBuilder.append(attributeType).append('=').append(string);
			}
		}
		return stringBuilder.toString();
	}

	public static String getString(ASN1Encodable attributeValue) {
		String string;
		if (attributeValue instanceof ASN1String) {
			string = ((ASN1String) attributeValue).getString();
		} else if (attributeValue instanceof ASN1ObjectIdentifier) {
			string = ((ASN1ObjectIdentifier) attributeValue).getId();
		} else {
			LOG.error("!!!*******!!! This encoding is unknown: {}", attributeValue.getClass().getSimpleName());
			string = attributeValue.toString();
			LOG.error("!!!*******!!! value: {}", string);
		}
		return string;
	}

	public static String extractAttributeFromX500Principal(ASN1ObjectIdentifier identifier, X500Principal x500PrincipalName) {
		final X500Name x500Name = X500Name.getInstance(x500PrincipalName.getEncoded());
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

	public static String getSubjectCommonName(CertificateToken cert) {
		return extractAttributeFromX500Principal(BCStyle.CN, cert.getSubjectX500Principal());
	}

	public static String getHumanReadableName(CertificateToken cert) {
		return firstNotNull(cert, BCStyle.CN, BCStyle.GIVENNAME, BCStyle.SURNAME, BCStyle.NAME, BCStyle.PSEUDONYM, BCStyle.O, BCStyle.OU);
	}

	private static String firstNotNull(CertificateToken cert, ASN1ObjectIdentifier... oids) {
		for (ASN1ObjectIdentifier oid : oids) {
			String value = extractAttributeFromX500Principal(oid, cert.getSubjectX500Principal());
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

	public static boolean isASN1SequenceTag(byte tagByte) {
		// BERTags.SEQUENCE | BERTags.CONSTRUCTED = 0x30
		return (BERTags.SEQUENCE | BERTags.CONSTRUCTED) == tagByte;
	}

	public static Date getDate(ASN1Encodable encodable) {
		try {
			return Time.getInstance(encodable).getDate();
		} catch (Exception e) {
			LOG.warn("Unable to retrieve the date : " + encodable, e);
			return null;
		}
	}

	public static boolean isEmpty(AttributeTable attributeTable) {
		return (attributeTable == null) || (attributeTable.size() == 0);
	}

	public static AttributeTable emptyIfNull(AttributeTable original) {
		if (original == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return original;
		}
	}

	public static List<String> getExtendedKeyUsage(CertificateToken certToken) {
		try {
			return certToken.getCertificate().getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			LOG.warn("Unable to retrieve ExtendedKeyUsage : {}", e.getMessage());
			return Collections.emptyList();
		}
	}

	public static IssuerSerialInfo getIssuerInfo(byte[] binaries) {
		try (ASN1InputStream is = new ASN1InputStream(binaries)) {
			ASN1Sequence seq = (ASN1Sequence) is.readObject();

			IssuerSerial issuerAndSerial = IssuerSerial.getInstance(seq);

			return getIssuerInfo(issuerAndSerial);
		} catch (Exception e) {
			LOG.error("Unable to decode IssuerSerialV2 textContent '" + Utils.toBase64(binaries) + "' : " + e.getMessage(), e);
			return null;
		}
	}

	public static IssuerSerialInfo getIssuerInfo(IssuerSerial issuerAndSerial) {
		try {
			IssuerSerialInfo issuerInfo = new IssuerSerialInfo();
			GeneralNames gnames = issuerAndSerial.getIssuer();
			if (gnames != null) {
				GeneralName[] names = gnames.getNames();
				if (names.length == 1) {
					issuerInfo.setIssuerName(new X500Principal(names[0].getName().toASN1Primitive().getEncoded(ASN1Encoding.DER)));
				} else {
					LOG.warn("More than one GeneralName");
				}
			}

			ASN1Integer serialNumber = issuerAndSerial.getSerial();
			if (serialNumber != null) {
				issuerInfo.setSerialNumber(serialNumber.getValue());
			}

			return issuerInfo;
		} catch (Exception e) {
			LOG.error("Unable to read the IssuerSerial object", e);
			return null;
		}
	}
	
	/**
	 * Returns {@link ASN1Encodable} for a given {@code oid} found in the {@code unsignedAttributes}
	 * @param unsignedAttributes {@link AttributeTable} of a signature
	 * @param oid target {@link ASN1ObjectIdentifier}
	 * @return {@link ASN1Encodable}
	 */
	public static ASN1Encodable getAsn1Encodable(AttributeTable unsignedAttributes, ASN1ObjectIdentifier oid) {
		final ASN1Set attrValues = getAsn1Atrribute(unsignedAttributes, oid);
		if (attrValues == null || attrValues.size() <= 0) {
			return null;
		}
		return attrValues.getObjectAt(0);
	}
	
	/**
	 * Returns an Attribute values for a given {@code oid} found in the {@code unsignedAttributes}
	 * @param unsignedAttributes {@link AttributeTable} of a signature
	 * @param oid target {@link ASN1ObjectIdentifier}
	 * @return {@link ASN1Set}
	 */
	public static ASN1Set getAsn1Atrribute(AttributeTable unsignedAttributes, ASN1ObjectIdentifier oid) {
		final Attribute attribute = unsignedAttributes.get(oid);
		if (attribute == null) {
			return null;
		}
		return attribute.getAttrValues();
	}
	
	/**
	 * Returns an array of {@link Attribute}s for a given {@code oid} found in the {@code unsignedAttributes}
	 * @param unsignedAttributes {@link AttributeTable} of a signature
	 * @param oid target {@link ASN1ObjectIdentifier}
	 * @return {@link Attribute}s array
	 */
	public static Attribute[] getAsn1Atrributes(AttributeTable unsignedAttributes, ASN1ObjectIdentifier oid) {
		ASN1EncodableVector encodableVector = unsignedAttributes.getAll(oid);
		if (encodableVector == null) {
			return null;
		}
		Attributes attributes = new Attributes(encodableVector);
		return attributes.getAttributes();
	}
	
	/**
	 * Finds {@link TimeStampToken}s with a given {@code oid}
	 * @param unsignedAttributes {@link AttributeTable} to obtain timestamps from
	 * @param oid {@link ASN1ObjectIdentifier} to collect
	 */
	public static List<TimeStampToken> findTimeStampTokens(AttributeTable unsignedAttributes, ASN1ObjectIdentifier oid) {
		List<TimeStampToken> timeStamps = new ArrayList<TimeStampToken>();
		Attribute[] signatureTimeStamps = getAsn1Atrributes(unsignedAttributes, oid);
		if (signatureTimeStamps != null) {
			for (final Attribute attribute : signatureTimeStamps) {
				try {
					ASN1Encodable value = attribute.getAttrValues().getObjectAt(0);
					if (value instanceof DEROctetString) {
						LOG.warn("Illegal content for timestamp (OID : {}) : OCTET STRING is not allowed !", oid.toString());
					} else {
						ASN1Primitive asn1Primitive = value.toASN1Primitive();
						CMSSignedData timeStampCMSSignedData = new CMSSignedData(asn1Primitive.getEncoded());
						timeStamps.add(new TimeStampToken(timeStampCMSSignedData));
					}
				} catch (IOException | CMSException | TSPException e) {
					LOG.warn("The given TimeStampToken cannot be created! Reason: [{}]", e.getMessage());
				}
			}
		}
		return timeStamps;
	}

}
