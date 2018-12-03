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
package eu.europa.esig.dss.crl;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.x509.CertificateToken;

public class CRLUtilsX509CRLImpl extends AbstractCRLUtils implements ICRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CRLUtilsX509CRLImpl.class);

	private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();

	private static final CertificateFactory CERT_FACTORY;

	static {
		try {
			Security.addProvider(BC_PROVIDER);
			CERT_FACTORY = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException("Platform does not support X509 certificate", e);
		} catch (NoSuchProviderException e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException("Platform does not support BouncyCastle", e);
		}
	}

	/**
	 * This method verifies: the signature of the CRL, the key usage of its signing certificate and the coherence
	 * between the subject names of the CRL signing
	 * certificate and the issuer name of the certificate for which the verification of the revocation data is carried
	 * out. A dedicated object based on
	 * {@code CRLValidity} is created and accordingly updated.
	 *
	 * @param crlStream
	 *            {@code InputStream} to be verified (cannot be null)
	 * @param issuerToken
	 *            {@code CertificateToken} used to sign the {@code X509CRL} (cannot be null)
	 * @return {@code CRLValidity}
	 */
	@Override
	public CRLValidity isValidCRL(final InputStream crlStream, final CertificateToken issuerToken) {

		final X509CRLValidity crlValidity = new X509CRLValidity();

		X509CRL x509CRL = loadCRL(crlStream);

		try {
			crlValidity.setX509CRL(x509CRL);
			crlValidity.setCrlEncoded(x509CRL.getEncoded());
		} catch (CRLException e) {
			LOG.error("Unable to read the CRL binaries", e);
		}

		final String sigAlgOID = x509CRL.getSigAlgOID();
		crlValidity.setSignatureAlgorithm(SignatureAlgorithm.forOID(sigAlgOID));
		crlValidity.setThisUpdate(x509CRL.getThisUpdate());
		crlValidity.setNextUpdate(x509CRL.getNextUpdate());

		final X500Principal x509CRLIssuerX500Principal = x509CRL.getIssuerX500Principal();
		final X500Principal issuerTokenSubjectX500Principal = issuerToken.getSubjectX500Principal();
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {
			crlValidity.setIssuerX509PrincipalMatches(true);
		}

		checkCriticalExtensions(crlValidity, x509CRL.getCriticalExtensionOIDs(), x509CRL.getExtensionValue(Extension.issuingDistributionPoint.getId()));
		extractExpiredCertsOnCRL(crlValidity, x509CRL.getExtensionValue(Extension.expiredCertsOnCRL.getId()));

		checkSignatureValue(x509CRL, issuerToken, crlValidity);
		if (crlValidity.isSignatureIntact()) {
			crlValidity.setCrlSignKeyUsage(issuerToken.checkKeyUsage(KeyUsageBit.crlSign));
		}
		return crlValidity;
	}

	private void checkSignatureValue(final X509CRL x509CRL, final CertificateToken issuerToken, final CRLValidity crlValidity) {
		try {
			x509CRL.verify(issuerToken.getPublicKey());
			crlValidity.setSignatureIntact(true);
			crlValidity.setIssuerToken(issuerToken);
		} catch (KeyException | CRLException | NoSuchAlgorithmException | SignatureException e) {
			crlValidity.setSignatureInvalidityReason(e.getClass().getSimpleName() + " - " + e.getMessage());
		} catch (NoSuchProviderException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public X509CRLEntry getRevocationInfo(CRLValidity crlValidity, BigInteger serialNumber) {
		X509CRL crl = getCRL(crlValidity);
		return crl.getRevokedCertificate(serialNumber);
	}

	private X509CRL getCRL(CRLValidity crlValidity) {
		X509CRL crl = null;
		if (crlValidity instanceof X509CRLValidity) {
			X509CRLValidity x509Validity = (X509CRLValidity) crlValidity;
			crl = x509Validity.getX509CRL();
		}
		if (crl == null) {
			crl = loadCRL(crlValidity.getCrlInputStream());
		}
		return crl;
	}

	/**
	 * This method loads a CRL from the given location.
	 *
	 * @param inputStream
	 *            the {@code InputStream}
	 * @return a new instance of {@code X509CRL}
	 */
	private X509CRL loadCRL(final InputStream inputStream) {
		try {
			X509CRL crl = (X509CRL) CERT_FACTORY.generateCRL(inputStream);
			if (crl == null) {
				throw new DSSException("Unable to parse the CRL");
			}
			return crl;
		} catch (CRLException e) {
			throw new DSSException(e);
		}
	}

}
