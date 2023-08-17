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
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.ResponderId;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Utility class used to manipulate revocation data (OCSP, CRL)
 *
 */
public final class DSSRevocationUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSRevocationUtils.class);

	/** Builds DigestCalculatorProvider */
	private static JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

	static {
		jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
	}

	private DSSRevocationUtils() {
		// empty
	}

	/**
	 * This method allows to create a {@code BasicOCSPResp} from a
	 * {@code ASN1Sequence}. The value for response SHALL be the DER encoding of
	 * BasicOCSPResponse (RFC 2560).
	 *
	 * @param asn1Sequence
	 *                     {@code ASN1Sequence} to convert to {@code BasicOCSPResp}
	 * @return {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp getBasicOcspResp(final ASN1Sequence asn1Sequence) {
		BasicOCSPResp basicOCSPResp = null;
		try {
			final BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(asn1Sequence);
			basicOCSPResp = new BasicOCSPResp(basicOcspResponse);
		} catch (Exception e) {
			LOG.warn("Impossible to create BasicOCSPResp from ASN1Sequence!", e);
		}
		return basicOCSPResp;
	}

	/**
	 * This method allows to create a {@code OCSPResp} from a {@code ASN1Sequence}.
	 *
	 * @param asn1Sequence
	 *                    {@code ASN1Sequence} to convert to {@code OCSPResp}
	 * @return {@code OCSPResp}
	 */
	public static OCSPResp getOcspResp(final ASN1Sequence asn1Sequence) {
		OCSPResp ocspResp = null;
		try {
			final OCSPResponse ocspResponse = OCSPResponse.getInstance(asn1Sequence);
			ocspResp = new OCSPResp(ocspResponse);
		} catch (Exception e) {
			LOG.warn("Impossible to create OCSPResp from ASN1Sequence!", e);
		}
		return ocspResp;
	}

	/**
	 * This method returns the {@code BasicOCSPResp} from a {@code OCSPResp}.
	 *
	 * @param ocspResp
	 *            {@code OCSPResp} to analysed
	 * @return {@link BasicOCSPResp}
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
			LOG.warn("Impossible to process OCSPResp!", e);
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
			throw new DSSException(String.format("Unable to convert BasicOCSPResp to OCSPResp : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets ASN1 encoded binaries of the {@code basicOCSPResp}
	 *
	 * @param basicOCSPResp {@link BasicOCSPResp}
	 * @return ASN1 encoded binaries
	 */
	public static byte[] getEncodedFromBasicResp(final BasicOCSPResp basicOCSPResp) {
		try {
			if (basicOCSPResp != null) {
				final OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(basicOCSPResp);
				return ocspResp.getEncoded();
			} else {
				throw new DSSException("Empty OCSP response");
			}
		} catch (IOException e) {
			throw new DSSException(String.format("OCSP encoding error : %s", e.getMessage()), e);
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
		return new OCSPResp(ocspResponse);
	}
	
	/**
	 * Returns a DigestAlgorithm used in the given {@code singleResp}
	 * 
	 * @param singleResp {@link SingleResp} to extract the used SingleResp from
	 * @return {@link SingleResp}
	 */
	public static DigestAlgorithm getUsedDigestAlgorithm(final SingleResp singleResp) {
		return DigestAlgorithm.forOID(singleResp.getCertID().getHashAlgOID().getId());
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
	 * @param digestAlgorithm
	 *            {@code DigestAlgorithm} to be used for CertificateID hash calculation
	 * @return {@code CertificateID}
	 */
	public static CertificateID getOCSPCertificateID(final CertificateToken cert, final CertificateToken issuerCert, 
			final DigestAlgorithm digestAlgorithm) {
		try {
			final BigInteger serialNumber = cert.getSerialNumber();
			final DigestCalculator digestCalculator = getDigestCalculator(digestAlgorithm);
			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(issuerCert);
			return new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
		} catch (OCSPException e) {
			throw new DSSException("Unable to create CertificateID", e);
		}
	}

	/**
	 * Gets a {@code DigestCalculator} for the {@code digestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @return {@link DigestCalculator}
	 */
	public static DigestCalculator getDigestCalculator(DigestAlgorithm digestAlgorithm) {
		try {
			final DigestCalculatorProvider digestCalculatorProvider = jcaDigestCalculatorProviderBuilder.build();
			return digestCalculatorProvider.get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm.getOid()), DERNull.INSTANCE));
		} catch (OperatorCreationException e) {
			throw new DSSException(
					String.format("Unable to create a DigestCalculator instance. DigestAlgorithm %s is not supported", digestAlgorithm.name()), e);
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

	/**
	 * Returns the encoded binaries of the OCSP response
	 *
	 * @param ocspResp {@link OCSPResp}
	 * @return ASN1 encoded binaries of the OCSP response
	 */
	public static byte[] getEncoded(OCSPResp ocspResp) {
		try {
			return ocspResp.getEncoded();
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to get binaries of OCSPResp : %s", e.getMessage()), e);
		}
	}
	
	/**
	 * Transforms {@link RespID} to {@link ResponderId}
	 * 
	 * @param respID {@link RespID} to get values from
	 * @return {@link ResponderId}
	 */
	public static ResponderId getDSSResponderId(RespID respID) {
		final ResponderID responderID = respID.toASN1Primitive();
		return getDSSResponderId(responderID);
	}

	/**
	 * Transforms {@link ResponderID} to {@link ResponderId}
	 * 
	 * @param responderID {@link ResponderID} to get values from
	 * @return {@link ResponderId}
	 */
	public static ResponderId getDSSResponderId(ResponderID responderID) {
		return new ResponderId(DSSASN1Utils.toX500Principal(responderID.getName()), responderID.getKeyHash());
	}
	
	/**
	 * Initialize a list revocation token keys {@link String} for {@link CRLToken} from the given {@link CertificateToken}
	 * 
	 * @param certificateToken {@link CertificateToken}
	 * @return list of {@link String} revocation keys
	 */
	public static List<String> getCRLRevocationTokenKeys(final CertificateToken certificateToken) {
		final List<String> revocationKeys = new ArrayList<>();
		final List<String> crlUrls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
		for (String crlUrl : crlUrls) {
			revocationKeys.add(getCRLRevocationTokenKey(crlUrl));
		}
		return revocationKeys;
	}

	/**
	 * Gets CRL key (SHA-1 digest) of the url
	 *
	 * @param crlUrl {@link String}
	 * @return {@link String}
	 */
	public static String getCRLRevocationTokenKey(final String crlUrl) {
		return DSSUtils.getSHA1Digest(crlUrl);
	}

	/**
	 * Initialize a list revocation token keys {@link String} for {@link OCSPToken} from the given {@link CertificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @return list of {@link String} revocation keys
	 */
	public static List<String> getOcspRevocationTokenKeys(final CertificateToken certificateToken) {
		final List<String> revocationKeys = new ArrayList<>();
		final List<String> ocspUrls = CertificateExtensionsUtils.getOCSPAccessUrls(certificateToken);
		for (String ocspUrl : ocspUrls) {
			revocationKeys.add(getOcspRevocationKey(certificateToken, ocspUrl));
		}
		return revocationKeys;
	}

	/**
	 * Gets OCSP key (SHA-1 digest) of the url
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param ocspUrl {@link String}
	 * @return {@link String}
	 */
	public static String getOcspRevocationKey(final CertificateToken certificateToken, final String ocspUrl) {
		return DSSUtils.getSHA1Digest(certificateToken.getDSSIdAsString() + ":" + ocspUrl);
	}

	/**
	 * Gets the latest single response from the OCSP response
	 *
	 * @param basicResponse {@link BasicOCSPResp}
	 * @param certificate {@link CertificateToken} to get single response for
	 * @param issuer {@link CertificateToken} issuer of the {@code certificate}
	 * @return {@link SingleResp}
	 */
	public static SingleResp getLatestSingleResponse(BasicOCSPResp basicResponse, CertificateToken certificate,
													 CertificateToken issuer) {
		List<SingleResp> singleResponses = getSingleResponses(basicResponse, certificate, issuer);
		if (Utils.isCollectionEmpty(singleResponses)) {
			return null;
		} else if (singleResponses.size() == 1) {
			return singleResponses.get(0);
		} else {
			return getLatestSingleRespInList(singleResponses);
		}
	}

	private static SingleResp getLatestSingleRespInList(List<SingleResp> singleResponses) {
		Date latest = null;
		SingleResp latestResp = null;
		for (SingleResp singleResp : singleResponses) {
			final Date thisUpdate = singleResp.getThisUpdate();
			if ((latest == null) || thisUpdate.after(latest)) {
				latestResp = singleResp;
				latest = thisUpdate;
			}
		}
		return latestResp;
	}

	/**
	 * Gets a list of single response from the OCSP response
	 *
	 * @param basicResponse {@link BasicOCSPResp}
	 * @param certificate {@link CertificateToken} to get single response for
	 * @param issuer {@link CertificateToken} issuer of the {@code certificate}
	 * @return a list of {@link SingleResp}onses
	 */
	public static List<SingleResp> getSingleResponses(BasicOCSPResp basicResponse, CertificateToken certificate,
													  CertificateToken issuer) {
		List<SingleResp> result = new ArrayList<>();
		SingleResp[] responses = getSingleResps(basicResponse);
		for (final SingleResp singleResp : responses) {
			DigestAlgorithm usedDigestAlgorithm = getUsedDigestAlgorithm(singleResp);
			final CertificateID certId = getOCSPCertificateID(certificate, issuer, usedDigestAlgorithm);
			if (DSSRevocationUtils.matches(certId, singleResp)) {
				result.add(singleResp);
			}
		}
		return result;
	}

	private static SingleResp[] getSingleResps(BasicOCSPResp basicResponse) {
		try {
			return basicResponse.getResponses();
		} catch (Exception e) {
			LOG.warn("Unable to extract SingleResp(s) : {}", e.getMessage());
			return new SingleResp[] {};
		}
	}

	/**
	 * Converts {@code OtherHash} to {@code Digest}
	 *
	 * @param otherHash {@link OtherHash}
	 * @return {@link Digest}
	 */
	public static Digest getDigest(OtherHash otherHash) {
		if (otherHash != null) {
			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(otherHash.getHashAlgorithm().getAlgorithm().getId());
			byte[] digestValue = otherHash.getHashValue();
			return new Digest(digestAlgorithm, digestValue);
		}
		return null;
	}

	/**
	 * Checks if the revocation has been produced during the issuer certificate validity range
	 *
	 * @param revocationToken {@link RevocationToken} to check
	 * @param issuerCertificateToken {@link CertificateToken} used to issue the current revocation data
	 * @return TRUE if the revocation producedAt time is in the issuer certificate's validity range, false otherwise
	 */
	public static boolean checkIssuerValidAtRevocationProductionTime(RevocationToken<?> revocationToken,
																	 CertificateToken issuerCertificateToken) {
		return issuerCertificateToken != null && issuerCertificateToken.isValidOn(revocationToken.getProductionDate());
	}

}
