/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.crl.stream.impl;

import eu.europa.esig.dss.crl.AbstractCRLUtils;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.crl.ICRLUtils;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
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
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.X509CRLEntry;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;

/**
 * The DSS implementation of {@code ICRLUtils}
 */
public class CRLUtilsStreamImpl extends AbstractCRLUtils implements ICRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CRLUtilsStreamImpl.class);

	/**
	 * Default constructor
	 */
	public CRLUtilsStreamImpl() {
		// empty
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
		extractCrlNumber(crlValidity, crlInfos.getNonCriticalExtension(Extension.cRLNumber.getId()));

		final X500Principal x509CRLIssuerX500Principal = crlInfos.getIssuer();
		final X500Principal issuerTokenSubjectX500Principal = issuerToken.getSubject().getPrincipal();
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {
			crlValidity.setIssuerX509PrincipalMatches(true);
		}

		checkSignatureValue(crlValidity, crlInfos.getSignatureValue(), signatureAlgorithm,
				crlInfos.getCertificateListSignatureAlgorithmParams(), getSignedData(crlValidity), issuerToken);
		
		return crlValidity;
	}

	private byte[] getSignedData(CRLValidity crlValidity) throws IOException {
		try (InputStream is = crlValidity.toCRLInputStream();
			 ByteArrayOutputStream baos = new ByteArrayOutputStream();
			 BinaryFilteringInputStream bfis = new BinaryFilteringInputStream(is, baos)) {
			CRLParser parser = new CRLParser();
			parser.getSignedData(bfis);
			return baos.toByteArray();
		}
	}

	@Override
	public X509CRLEntry getRevocationInfo(CRLValidity crlValidity, BigInteger serialNumber) {
		CRLParser parser = new CRLParser();
		X509CRLEntry crlEntry = null;
		try (InputStream is = crlValidity.toCRLInputStream()) {
			crlEntry = parser.retrieveRevocationInfo(is, serialNumber);
		} catch (IOException e) {
			LOG.warn("Unable to retrieve the revocation status", e);
		}
		return crlEntry;
	}

	private void checkSignatureValue(CRLValidity crlValidity, byte[] signatureValue, SignatureAlgorithm signatureAlgorithm,
									 byte[] params, byte[] signedData, CertificateToken signer) {
		try {
			Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
			AlgorithmParameterSpec algoParamSpec = createAlgoParamSpec(signatureAlgorithm, params);
			if (algoParamSpec != null) {
				signature.setParameter(algoParamSpec);
			}
			signature.initVerify(signer.getPublicKey());
			signature.update(signedData);
			if (signature.verify(signatureValue)) {
				crlValidity.setSignatureIntact(true);
				crlValidity.setIssuerToken(signer);

				boolean crlSign = signer.checkKeyUsage(KeyUsageBit.CRL_SIGN);
				if (!crlSign) {
					crlValidity.setSignatureInvalidityReason(
							String.format("CRL issuer does not have '%s' key usage!", KeyUsageBit.CRL_SIGN.getValue()));
				}
				crlValidity.setCrlSignKeyUsage(crlSign);

			} else {
				crlValidity.setSignatureInvalidityReason("CRL Signature is not intact.");
			}

		} catch (Exception e) {
			String msg = String.format("CRL Signature cannot be validated : %s", e.getMessage());
			if (LOG.isTraceEnabled()) {
				LOG.trace(msg, e);
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

	private AlgorithmParameterSpec createAlgoParamSpec(SignatureAlgorithm signatureAlgorithm, byte[] params)
			throws NoSuchAlgorithmException, IOException, InvalidParameterSpecException {
		if (params == null) {
			return null;
		}

		AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signatureAlgorithm.getJCEId());
		sigParams.init(params);
		if (EncryptionAlgorithm.RSASSA_PSS == signatureAlgorithm.getEncryptionAlgorithm()) {
			return sigParams.getParameterSpec(PSSParameterSpec.class);
		}
		LOG.warn("Only RSASSA_PSS signature parameters are supported!");
		return null;
	}

}
