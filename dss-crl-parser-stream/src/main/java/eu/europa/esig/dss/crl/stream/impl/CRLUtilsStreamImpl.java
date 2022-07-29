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
package eu.europa.esig.dss.crl.stream.impl;

import eu.europa.esig.dss.crl.AbstractCRLUtils;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.crl.ICRLUtils;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509CRLEntry;

/**
 * The DSS implementation of {@code ICRLUtils}
 */
public class CRLUtilsStreamImpl extends AbstractCRLUtils implements ICRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CRLUtilsStreamImpl.class);

	/**
	 * Default constructor
	 */
	public CRLUtilsStreamImpl() {
	}

	@Override
	public CRLValidity buildCRLValidity(CRLBinary crlBinary, CertificateToken issuerToken) throws IOException {
		
		final CRLValidity crlValidity = new CRLValidity(crlBinary);
		
		CRLInfo crlInfos = getCrlInfo(crlValidity);
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOidAndParams(crlInfos.getCertificateListSignatureAlgorithmOid(),
				crlInfos.getCertificateListSignatureAlgorithmParams());
		crlValidity.setSignatureAlgorithm(signatureAlgorithm);

		crlValidity.setThisUpdate(crlInfos.getThisUpdate());
		crlValidity.setNextUpdate(crlInfos.getNextUpdate());

		crlValidity.setCriticalExtensionsOid(crlInfos.getCriticalExtensions().keySet());
		extractIssuingDistributionPointBinary(crlValidity, crlInfos.getCriticalExtension(Extension.issuingDistributionPoint.getId()));
		extractExpiredCertsOnCRL(crlValidity, crlInfos.getNonCriticalExtension(Extension.expiredCertsOnCRL.getId()));

		final X500Principal x509CRLIssuerX500Principal = crlInfos.getIssuer();
		final X500Principal issuerTokenSubjectX500Principal = issuerToken.getSubject().getPrincipal();
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {
			crlValidity.setIssuerX509PrincipalMatches(true);
		}

		checkSignatureValue(crlValidity, crlInfos.getSignatureValue(), signatureAlgorithm, getSignedData(crlValidity), issuerToken);
		
		return crlValidity;
	}

	private ByteArrayOutputStream getSignedData(CRLValidity crlValidity) throws IOException {
		try (InputStream is = crlValidity.toCRLInputStream()) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			BinaryFilteringInputStream bfis = new BinaryFilteringInputStream(is, baos);
			CRLParser parser = new CRLParser();
			parser.getSignedData(bfis);
			return baos;
		}
	}

	@Override
	public X509CRLEntry getRevocationInfo(CRLValidity crlValidity, BigInteger serialNumber) {
		CRLParser parser = new CRLParser();
		X509CRLEntry crlEntry = null;
		try (InputStream is = crlValidity.toCRLInputStream()) {
			crlEntry = parser.retrieveRevocationInfo(is, serialNumber);
		} catch (IOException e) {
			LOG.error("Unable to retrieve the revocation status", e);
		}
		return crlEntry;
	}

	private void checkSignatureValue(CRLValidity crlValidity, byte[] signatureValue, SignatureAlgorithm signatureAlgorithm, ByteArrayOutputStream baos,
			CertificateToken signer) {
		try {
			Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
			signature.initVerify(signer.getPublicKey());
			signature.update(baos.toByteArray());
			if (signature.verify(signatureValue)) {
				crlValidity.setSignatureIntact(true);
				crlValidity.setIssuerToken(signer);
				crlValidity.setCrlSignKeyUsage(signer.checkKeyUsage(KeyUsageBit.CRL_SIGN));
			} else {
				crlValidity.setSignatureInvalidityReason("Signature value not correct");
			}
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

	private CRLInfo getCrlInfo(CRLValidity crlValidity) throws IOException {
		try (InputStream is = crlValidity.toCRLInputStream(); BufferedInputStream bis = new BufferedInputStream(is)) {
			CRLParser parser = new CRLParser();
			return parser.retrieveInfo(bis);
		}
	}

}
