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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ResponderId;
import eu.europa.esig.dss.utils.Utils;

/**
 * Utility class used to manipulate revocation data (OCSP, CRL)
 *
 */
public final class DSSRevocationUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSRevocationUtils.class);

	private static JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

	static {
		jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
	}

	private DSSRevocationUtils() {
	}

	/**
	 * This method allows to create a {@code BasicOCSPResp} from a {@code DERSequence}.
	 * The value for response SHALL be the DER encoding of BasicOCSPResponse (RFC 2560).
	 *
	 * @param derSequence
	 *            {@code DERSequence} to convert to {@code BasicOCSPResp}
	 * @return {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp getBasicOcspResp(final DERSequence derSequence) {
		BasicOCSPResp basicOCSPResp = null;
		try {
			final BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(derSequence);
			basicOCSPResp = new BasicOCSPResp(basicOcspResponse);
		} catch (Exception e) {
			LOG.error("Impossible to create BasicOCSPResp from DERSequence!", e);
		}
		return basicOCSPResp;
	}

	/**
	 * This method allows to create a {@code OCSPResp} from a {@code DERSequence}.
	 *
	 * @param derSequence
	 *            {@code DERSequence} to convert to {@code OCSPResp}
	 * @return {@code OCSPResp}
	 */
	public static OCSPResp getOcspResp(final DERSequence derSequence) {
		OCSPResp ocspResp = null;
		try {
			final OCSPResponse ocspResponse = OCSPResponse.getInstance(derSequence);
			ocspResp = new OCSPResp(ocspResponse);
		} catch (Exception e) {
			LOG.error("Impossible to create OCSPResp from DERSequence!", e);
		}
		return ocspResp;
	}

	/**
	 * This method returns the {@code BasicOCSPResp} from a {@code OCSPResp}.
	 *
	 * @param ocspResp
	 *            {@code OCSPResp} to analysed
	 * @return
	 */
	public static BasicOCSPResp fromRespToBasic(final OCSPResp ocspResp) {
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
	 * Convert a BasicOCSPResp in OCSPResp (connection status is set to
	 * SUCCESSFUL).
	 *
	 * @param basicOCSPResp
	 *            the {@code BasicOCSPResp} to be converted to {@code OCSPResp}
	 * @return the result of the conversion
	 */
	public static OCSPResp fromBasicToResp(final BasicOCSPResp basicOCSPResp) {
		try {
			final byte[] encoded = basicOCSPResp.getEncoded();
			return fromBasicToResp(encoded);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	public static byte[] getEncodedFromBasicResp(final BasicOCSPResp basicOCSPResp) {
		try {
			if (basicOCSPResp != null) {
				final OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(basicOCSPResp);
				return ocspResp.getEncoded();
			} else {
				throw new DSSException("Empty OCSP response");
			}
		} catch (IOException e) {
			throw new DSSException("OCSP encoding error: " + e.getMessage(), e);
		}
	}

	/**
	 * Convert a BasicOCSPResp in OCSPResp (connection status is set to
	 * SUCCESSFUL).
	 *
	 * @param basicOCSPRespBinary
	 *            the binary of BasicOCSPResp
	 * @return an instance of OCSPResp
	 */
	public static OCSPResp fromBasicToResp(final byte[] basicOCSPRespBinary) {
		final OCSPResponseStatus responseStatus = new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL);
		final DEROctetString derBasicOCSPResp = new DEROctetString(basicOCSPRespBinary);
		final ResponseBytes responseBytes = new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic, derBasicOCSPResp);
		final OCSPResponse ocspResponse = new OCSPResponse(responseStatus, responseBytes);
		// !!! todo to be checked: System.out.println("===> RECREATED: " +
		// ocspResp.hashCode());
		return new OCSPResp(ocspResponse);
	}

	/**
	 * fix for certId.equals methods that doesn't work very well.
	 *
	 * @param certId
	 *            {@code CertificateID}
	 * @param singleResp
	 *            {@code SingleResp}
	 * @return true if the certificate matches this included in
	 *         {@code SingleResp}
	 */
	public static boolean matches(final CertificateID certId, final SingleResp singleResp) {

		final CertificateID singleRespCertID = singleResp.getCertID();
		final ASN1ObjectIdentifier singleRespCertIDHashAlgOID = singleRespCertID.getHashAlgOID();
		final byte[] singleRespCertIDIssuerKeyHash = singleRespCertID.getIssuerKeyHash();
		final byte[] singleRespCertIDIssuerNameHash = singleRespCertID.getIssuerNameHash();
		final BigInteger singleRespCertIDSerialNumber = singleRespCertID.getSerialNumber();

		final ASN1ObjectIdentifier certIdHashAlgOID = certId.getHashAlgOID();
		final byte[] certIdIssuerKeyHash = certId.getIssuerKeyHash();
		final byte[] certIdIssuerNameHash = certId.getIssuerNameHash();
		final BigInteger certIdSerialNumber = certId.getSerialNumber();

		// certId.equals fails in comparing the algoIdentifier because
		// AlgoIdentifier params in null in one case and DERNull in another case
		return singleRespCertIDHashAlgOID.equals(certIdHashAlgOID) && Arrays.equals(singleRespCertIDIssuerKeyHash, certIdIssuerKeyHash)
				&& Arrays.equals(singleRespCertIDIssuerNameHash, certIdIssuerNameHash) && singleRespCertIDSerialNumber.equals(certIdSerialNumber);
	}

	/**
	 * Returns the {@code CertificateID} for the given certificate and its
	 * issuer's certificate.
	 *
	 * @param cert
	 *            {@code CertificateToken} for which the id is created
	 * @param issuerCert
	 *            {@code CertificateToken} issuer certificate of the {@code cert}
	 * @return {@code CertificateID}
	 */
	public static CertificateID getOCSPCertificateID(final CertificateToken cert, final CertificateToken issuerCert) {
		try {
			final BigInteger serialNumber = cert.getSerialNumber();
			final DigestCalculator digestCalculator = getSHA1DigestCalculator();
			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(issuerCert);
			return new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
		} catch (OCSPException e) {
			throw new DSSException("Unable to create CertificateID", e);
		}
	}

	public static DigestCalculator getSHA1DigestCalculator() {
		try {
			final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
			return digestCalculatorProvider.get(CertificateID.HASH_SHA1);
		} catch (OperatorCreationException e) {
			throw new DSSException("Unable to create a DigestCalculator instance", e);
		}
	}

	/**
	 * This method loads an OCSP response from the given base 64 encoded string.
	 *
	 * @param base64Encoded
	 *            base 64 encoded OCSP response
	 * @return the {@code BasicOCSPResp} object
	 * @throws IOException
	 *             if IO error occurred
	 */
	public static BasicOCSPResp loadOCSPBase64Encoded(final String base64Encoded) throws IOException {
		final byte[] derEncoded = Utils.fromBase64(base64Encoded);
		return loadOCSPFromBinaries(derEncoded);
	}

	/**
	 * This method loads an OCSP response from the given binaries.
	 *
	 * @param binaries
	 *            byte array of OCSP response
	 * @return the {@code BasicOCSPResp} object
	 * @throws IOException
	 *             if IO error occurred
	 */
	public static BasicOCSPResp loadOCSPFromBinaries(final byte[] binaries) throws IOException {
		final OCSPResp ocspResp = new OCSPResp(binaries);
		return fromRespToBasic(ocspResp);
	}

	public static byte[] getEncoded(OCSPResp ocspResp) {
		try {
			return ocspResp.getEncoded();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	/**
	 * Transforms {@link RespID} to {@link ResponderId}
	 * @param respID {@link RespID} to get values from
	 * @return {@link ResponderId}
	 */
	public static ResponderId getDSSResponderId(RespID respID) {
		ResponderId dssResponderId = new ResponderId();
		final ResponderID responderIdAsASN1Object = respID.toASN1Primitive();
		final DERTaggedObject derTaggedObject = (DERTaggedObject) responderIdAsASN1Object.toASN1Primitive();
		if (2 == derTaggedObject.getTagNo()) {
			final ASN1OctetString keyHashOctetString = (ASN1OctetString) derTaggedObject.getObject();
			final byte[] keyHashOctetStringBytes = keyHashOctetString.getOctets();
			dssResponderId.setKey(keyHashOctetStringBytes);
			return dssResponderId;
		} else {
			final ASN1Primitive derObject = derTaggedObject.getObject();
			final X500Name name = X500Name.getInstance(derObject);
			dssResponderId.setName(name.toString());
			return dssResponderId;
		}
	}
	
	/**
	 * Creates the identifier for a certain entry within jdbc.
	 *
	 * @param certificateToken
	 *            {@link CertificateToken}
	 * @param issuerCertificateToken
	 *            {@link CertificateToken} of the issuer of the certificateToken
	 * @return the identifier for jdbc
	 */
	public static String getJdbcKey(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		final StringBuilder buf = new StringBuilder(certificateToken.getEntityKey());
		buf.append(":").append(issuerCertificateToken.getEntityKey());
		return buf.toString();
	}
	
	/**
	 * Initialize a list revocation token keys {@link String} for {@link CRLToken} from the given {@link CertificateToken}
	 * @param certificateToken {@link CertificateToken}
	 * @return list of {@link String} revocation keys
	 */
	public static List<String> getCRLRevocationTokenKeys(final CertificateToken certificateToken) {
		final List<String> crlUrls = DSSASN1Utils.getCrlUrls(certificateToken);
		List<String> revocationKeys = new ArrayList<String>();
		for (String crlUrl : crlUrls) {
			revocationKeys.add(getCRLRevocationTokenKey(crlUrl));
		}
		return revocationKeys;
	}
	
	public static String getCRLRevocationTokenKey(final String crlUrl) {
		return DSSUtils.getSHA1Digest(crlUrl);
	}

	/**
	 * Initialize a list revocation token keys {@link String} for {@link OCSPToken} from the given {@link CertificateToken}
	 * @param certificateToken {@link CertificateToken}
	 * @return list of {@link String} revocation keys
	 */
	public static List<String> getOcspRevocationTokenKeys(final CertificateToken certificateToken) {
		final List<String> ocspUrls = DSSASN1Utils.getOCSPAccessLocations(certificateToken);
		List<String> revocationKeys = new ArrayList<String>();
		for (String ocspUrl : ocspUrls) {
			revocationKeys.add(getOcspRevocationKey(certificateToken, ocspUrl));
		}
		return revocationKeys;
	}
	
	public static String getOcspRevocationKey(final CertificateToken certificateToken, final String ocspUrl) {
		return DSSUtils.getSHA1Digest(certificateToken.getEntityKey() + ":" + ocspUrl);
	}

}
