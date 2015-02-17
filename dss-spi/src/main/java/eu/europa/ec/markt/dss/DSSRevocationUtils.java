/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.RevocationToken;

/**
 * Utility class used to convert OCSPResp to BasicOCSPResp
 *
 * @version $Revision$ - $Date$
 */

public final class DSSRevocationUtils {

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
			throw new RuntimeException(e);
		}
	}

	/**
	 * Convert a BasicOCSPResp in OCSPResp (connection status is set to SUCCESSFUL).
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
	 * Convert a BasicOCSPResp in OCSPResp (connection status is set to SUCCESSFUL).
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
		//!!! todo to be checked: System.out.println("===> RECREATED: " + ocspResp.hashCode());
		return ocspResp;
	}

	/**
	 * This method indicates if the given revocation token is present in the CRL or OCSP response list.
	 *
	 * @param revocationToken    revocation token to be checked
	 * @param basicOCSPResponses list of basic OCSP responses
	 * @return true if revocation token is present in one of the lists
	 */
	public static boolean isTokenIn(final RevocationToken revocationToken, final List<BasicOCSPResp> basicOCSPResponses) {

		if (revocationToken instanceof OCSPToken && basicOCSPResponses != null) {

			final BasicOCSPResp basicOCSPResp = ((OCSPToken) revocationToken).getBasicOCSPResp();
			final boolean contains = basicOCSPResponses.contains(basicOCSPResp);
			return contains;
		}
		return false;
	}

	/**
	 * This method returns the reason of the revocation of the certificate extracted from the given CRL.
	 *
	 * @param crlEntry An object for a revoked certificate in a CRL (Certificate Revocation List).
	 * @return
	 * @throws DSSException
	 */
	public static String getRevocationReason(final X509CRLEntry crlEntry) throws DSSException {

		final String reasonId = Extension.reasonCode.getId();
		final byte[] extensionBytes = crlEntry.getExtensionValue(reasonId);
		ASN1InputStream asn1InputStream = null;
		try {

			asn1InputStream = new ASN1InputStream(extensionBytes);
			final ASN1Enumerated asn1Enumerated = ASN1Enumerated.getInstance(asn1InputStream.readObject());
			final CRLReason reason = CRLReason.getInstance(asn1Enumerated);
			return reason.toString();
		} catch (IllegalArgumentException e) {
			// In the test case XAdESTest003 testTRevoked() there is an error in the revocation reason.
			//LOG.warn("Error when revocation reason decoding from CRL: " + e.toString());
			final CRLReason reason = CRLReason.lookup(7); // 7 -> unknown
			return reason.toString(); // unknown
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {

			DSSUtils.closeQuietly(asn1InputStream);
		}
	}

	/**
	 * fix for certId.equals methods that doesn't work very well.
	 *
	 * @param certId     {@code CertificateID}
	 * @param singleResp {@code SingleResp}
	 * @return true if the certificate matches this included in {@code SingleResp}
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

		// certId.equals fails in comparing the algoIdentifier because AlgoIdentifier params in null in one case and DERNull in another case
		return singleRespCertIDHashAlgOID.equals(certIdHashAlgOID) && Arrays.areEqual(singleRespCertIDIssuerKeyHash, certIdIssuerKeyHash) && Arrays
			  .areEqual(singleRespCertIDIssuerNameHash, certIdIssuerNameHash) &&
			  singleRespCertIDSerialNumber.equals(certIdSerialNumber);
	}

	/**
	 * Returns the {@code CertificateID} for the given certificate and its issuer's certificate.
	 *
	 * @param cert       {@code X509Certificate} for which the id is created
	 * @param issuerCert {@code X509Certificate} issuer certificate of the {@code cert}
	 * @return {@code CertificateID}
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	public static CertificateID getOCSPCertificateID(final X509Certificate cert, final X509Certificate issuerCert) throws DSSException {

		try {

			final BigInteger serialNumber = cert.getSerialNumber();
			final DigestCalculator digestCalculator = DSSUtils.getSHA1DigestCalculator();
			final X509CertificateHolder x509CertificateHolder = DSSUtils.getX509CertificateHolder(issuerCert);
			final CertificateID certificateID = new CertificateID(digestCalculator, x509CertificateHolder, serialNumber);
			return certificateID;
		} catch (OCSPException e) {
			throw new DSSException(e);
		}
	}
}
