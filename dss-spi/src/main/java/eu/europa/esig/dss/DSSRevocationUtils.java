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
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Utility class used to convert OCSPResp to BasicOCSPResp
 *
 *
 */

public final class DSSRevocationUtils {

	private static JcaDigestCalculatorProviderBuilder jcaDigestCalculatorProviderBuilder;

	static {
		jcaDigestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
		jcaDigestCalculatorProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

	private DSSRevocationUtils() {
	}

	/**
	 * Convert a OCSPResp in a BasicOCSPResp
	 *
	 * @param ocspResp
	 * @return
	 */
	public static final BasicOCSPResp fromRespToBasic(OCSPResp ocspResp) {
		try {
			return (BasicOCSPResp) ocspResp.getResponseObject();
		} catch (OCSPException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Convert a BasicOCSPResp in OCSPResp (connection status is set to
	 * SUCCESSFUL).
	 *
	 * @param basicOCSPResp
	 * @return
	 */
	public static final OCSPResp fromBasicToResp(final BasicOCSPResp basicOCSPResp) {
		try {
			final byte[] encoded = basicOCSPResp.getEncoded();
			final OCSPResp ocspResp = fromBasicToResp(encoded);
			return ocspResp;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Convert a BasicOCSPResp in OCSPResp (connection status is set to
	 * SUCCESSFUL).
	 *
	 * @param basicOCSPResp
	 * @return
	 */
	public static final OCSPResp fromBasicToResp(final byte[] basicOCSPResp) {
		final OCSPResponseStatus responseStatus = new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL);
		final DEROctetString derBasicOCSPResp = new DEROctetString(basicOCSPResp);
		final ResponseBytes responseBytes = new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic, derBasicOCSPResp);
		final OCSPResponse ocspResponse = new OCSPResponse(responseStatus, responseBytes);
		final OCSPResp ocspResp = new OCSPResp(ocspResponse);
		// !!! todo to be checked: System.out.println("===> RECREATED: " +
		// ocspResp.hashCode());
		return ocspResp;
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
	 * @throws eu.europa.esig.dss.DSSException
	 */
	public static CertificateID getOCSPCertificateID(final CertificateToken cert, final CertificateToken issuerCert) throws DSSException {
		try {
			final BigInteger serialNumber = cert.getSerialNumber();
			final DigestCalculator digestCalculator = getSHA1DigestCalculator();
			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(issuerCert);
			final CertificateID certificateID = new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
			return certificateID;
		} catch (OCSPException e) {
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
	 * This method loads an OCSP response from the given base 64 encoded string.
	 *
	 * @param base64Encoded
	 *            base 64 encoded OCSP response
	 * @return {@code BasicOCSPResp}
	 * @throws IOException
	 * @throws OCSPException
	 */
	public static BasicOCSPResp loadOCSPBase64Encoded(final String base64Encoded) throws IOException, OCSPException {
		final byte[] derEncoded = Utils.fromBase64(base64Encoded);
		final OCSPResp ocspResp = new OCSPResp(derEncoded);
		final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
		return basicOCSPResp;
	}

	public static byte[] getEncoded(OCSPResp ocspResp) {
		try {
			final byte[] encoded = ocspResp.getEncoded();
			return encoded;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

}
