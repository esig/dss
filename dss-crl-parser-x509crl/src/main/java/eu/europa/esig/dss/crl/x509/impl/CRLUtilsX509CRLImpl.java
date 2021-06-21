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
package eu.europa.esig.dss.crl.x509.impl;

import eu.europa.esig.dss.crl.AbstractCRLUtils;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.crl.ICRLUtils;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

/**
 * The implementation of {@code ICRLUtils} with java.security classes
 */
public class CRLUtilsX509CRLImpl extends AbstractCRLUtils implements ICRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CRLUtilsX509CRLImpl.class);

	/**
	 * This method verifies: the signature of the CRL, the key usage of its signing certificate and the coherence
	 * between the subject names of the CRL signing
	 * certificate and the issuer name of the certificate for which the verification of the revocation data is carried
	 * out. A dedicated object based on
	 * {@code CRLValidity} is created and accordingly updated.
	 *
	 * @param crlBinary
	 *            {@code CRLBinary} of the CRL to be created (cannot be null)
	 * @param issuerToken
	 *            {@code CertificateToken} used to sign the {@code X509CRL} (cannot be null)
	 * @return {@code CRLValidity}
	 */
	@Override
	public CRLValidity buildCRLValidity(final CRLBinary crlBinary, final CertificateToken issuerToken) throws IOException {
		
		final X509CRLValidity crlValidity= new X509CRLValidity(crlBinary);
		
		try (InputStream bais = crlValidity.toCRLInputStream()) {
			
			X509CRL x509CRL = loadCRL(bais);
			crlValidity.setX509CRL(x509CRL);

			final String sigAlgOID = x509CRL.getSigAlgOID();
			final byte[] sigAlgParams = x509CRL.getSigAlgParams();
			crlValidity.setSignatureAlgorithm(SignatureAlgorithm.forOidAndParams(sigAlgOID, sigAlgParams));
			crlValidity.setThisUpdate(x509CRL.getThisUpdate());
			crlValidity.setNextUpdate(x509CRL.getNextUpdate());

			final X500Principal x509CRLIssuerX500Principal = x509CRL.getIssuerX500Principal();
			final X500Principal issuerTokenSubjectX500Principal = issuerToken.getSubject().getPrincipal();
			if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {
				crlValidity.setIssuerX509PrincipalMatches(true);
			}

			crlValidity.setCriticalExtensionsOid(x509CRL.getCriticalExtensionOIDs());
			extractIssuingDistributionPointBinary(crlValidity, x509CRL.getExtensionValue(Extension.issuingDistributionPoint.getId()));
			extractExpiredCertsOnCRL(crlValidity, x509CRL.getExtensionValue(Extension.expiredCertsOnCRL.getId()));

			checkSignatureValue(x509CRL, issuerToken, crlValidity);
			if (crlValidity.isSignatureIntact()) {
				crlValidity.setCrlSignKeyUsage(issuerToken.checkKeyUsage(KeyUsageBit.CRL_SIGN));
			}
			
		}
		
		return crlValidity;
		
	}

	private void checkSignatureValue(final X509CRL x509CRL, final CertificateToken issuerToken, final CRLValidity crlValidity) {
		try {
			x509CRL.verify(issuerToken.getPublicKey());
			crlValidity.setSignatureIntact(true);
			crlValidity.setIssuerToken(issuerToken);
		} catch (GeneralSecurityException e) {
			String msg = String.format("CRL Signature cannot be validated : %s", e.getMessage());
			if (LOG.isTraceEnabled()) {
				LOG.trace(msg, e);
			} else {
				LOG.warn(msg);
			}
			crlValidity.setSignatureInvalidityReason(msg);
		}
	}

	@Override
	public X509CRLEntry getRevocationInfo(CRLValidity crlValidity, BigInteger serialNumber) {
		X509CRL crl = null;
		if (crlValidity instanceof X509CRLValidity) {
			crl = ((X509CRLValidity) crlValidity).getX509CRL();
		}
		if (crl == null) {
			try (InputStream is = crlValidity.toCRLInputStream()) {
				crl = loadCRL(is);
			} catch (IOException e) {
				throw new DSSException(String.format("Unable to get revocation info. Reason : %s", e.getMessage()), e);
			}
		}
		return crl.getRevokedCertificate(serialNumber);
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
			X509CRL crl = (X509CRL) getCertificateFactory().generateCRL(inputStream);
			if (crl == null) {
				throw new DSSException("Unable to parse the CRL");
			}
			return crl;
		} catch (CRLException e) {
			throw new DSSException(String.format("Unable to parse the CRL : %s", e.getMessage()), e);
		}
	}

	private CertificateFactory getCertificateFactory() {
		try {
			// TODO extract BC
			CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
			LOG.debug("CertificateFactory instantiated with BouncyCastle");
			return cf;
		} catch (CertificateException | NoSuchProviderException e) {
			LOG.debug("Unable to instantiate with BouncyCastle (not registered ?), trying with default CertificateFactory");
			try {
				return CertificateFactory.getInstance("X.509");
			} catch (CertificateException e1) {
				throw new DSSException("Unable to create CertificateFactory", e1);
			}
		}
	}

}
