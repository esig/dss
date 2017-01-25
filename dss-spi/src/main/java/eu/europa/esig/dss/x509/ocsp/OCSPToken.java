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
package eu.europa.esig.dss.x509.ocsp;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.TokenValidationExtraInfo;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;

/**
 * OCSP Signed Token which encapsulate BasicOCSPResp (BC).
 */
@SuppressWarnings("serial")
public class OCSPToken extends RevocationToken {

	private static final Logger logger = LoggerFactory.getLogger(OCSPToken.class);

	private CertificateID certId;

	/**
	 * Status of the OCSP response
	 */
	private OCSPRespStatus responseStatus;

	/**
	 * The OCSP request contained a nonce
	 */
	private boolean useNonce;

	/**
	 * The sent nonce matched with the received one
	 */
	private boolean nonceMatch;

	/**
	 * The encapsulated basic OCSP response.
	 */
	private BasicOCSPResp basicOCSPResp;

	public OCSPToken() {
		this.extraInfo = new TokenValidationExtraInfo();
	}

	public void extractInfo() {
		if (basicOCSPResp != null) {
			this.productionDate = basicOCSPResp.getProducedAt();
			this.signatureAlgorithm = SignatureAlgorithm.forOID(basicOCSPResp.getSignatureAlgOID().getId());
			extractArchiveCutOff();

			SingleResp bestSingleResp = getBestSingleResp(basicOCSPResp, certId);
			if (bestSingleResp != null) {
				this.thisUpdate = bestSingleResp.getThisUpdate();
				this.nextUpdate = bestSingleResp.getNextUpdate();
				extractStatusInfo(bestSingleResp);
			}
		}
	}

	private SingleResp getBestSingleResp(final BasicOCSPResp basicOCSPResp, final CertificateID certId) {
		Date bestUpdate = null;
		SingleResp bestSingleResp = null;
		SingleResp[] responses = getResponses(basicOCSPResp);
		for (final SingleResp singleResp : responses) {
			if (DSSRevocationUtils.matches(certId, singleResp)) {
				final Date thisUpdate = singleResp.getThisUpdate();
				if ((bestUpdate == null) || thisUpdate.after(bestUpdate)) {
					bestSingleResp = singleResp;
					bestUpdate = thisUpdate;
				}
			}
		}
		return bestSingleResp;
	}

	private SingleResp[] getResponses(final BasicOCSPResp basicOCSPResp) {
		SingleResp[] responses = new SingleResp[] {};
		try {
			responses = basicOCSPResp.getResponses();
		} catch (Exception e) {
			logger.error("Unable to parse the responses object from OCSP", e);
			extraInfo.infoOCSPException("Unable to parse the responses object from OCSP : " + e.getMessage());
		}
		return responses;
	}

	private void extractStatusInfo(SingleResp bestSingleResp) {
		CertificateStatus certStatus = bestSingleResp.getCertStatus();
		if (CertificateStatus.GOOD == certStatus) {
			if (logger.isInfoEnabled()) {
				logger.info("OCSP status is good");
			}
			status = true;
		} else if (certStatus instanceof RevokedStatus) {
			if (logger.isInfoEnabled()) {
				logger.info("OCSP status revoked");
			}
			final RevokedStatus revokedStatus = (RevokedStatus) certStatus;
			status = false;
			revocationDate = revokedStatus.getRevocationTime();
			int reasonId = 0; // unspecified
			if (revokedStatus.hasRevocationReason()) {
				reasonId = revokedStatus.getRevocationReason();
			}
			reason = CRLReasonEnum.fromInt(reasonId).name();
		} else if (certStatus instanceof UnknownStatus) {
			if (logger.isInfoEnabled()) {
				logger.info("OCSP status unknown");
			}
			reason = CRLReasonEnum.unknow.name();
		} else {
			logger.info("OCSP certificate status: " + certStatus);
		}
	}

	private void extractArchiveCutOff() {
		Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
		if (extension != null) {
			ASN1GeneralizedTime archiveCutOffAsn1 = (ASN1GeneralizedTime) extension.getParsedValue();
			try {
				archiveCutOff = archiveCutOffAsn1.getDate();
			} catch (ParseException e) {
				logger.warn("Unable to extract id_pkix_ocsp_archive_cutoff : " + e.getMessage());
			}
		}
	}

	@Override
	public boolean isSignedBy(final CertificateToken issuerToken) {
		if (this.issuerToken != null) {
			return this.issuerToken.equals(issuerToken);
		}
		if (basicOCSPResp == null) {
			return false;
		}
		try {
			signatureInvalidityReason = "";
			JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
			jcaContentVerifierProviderBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
			final PublicKey publicKey = issuerToken.getCertificate().getPublicKey();
			ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(publicKey);
			signatureValid = basicOCSPResp.isSignatureValid(contentVerifierProvider);
			if (signatureValid) {
				this.issuerToken = issuerToken;
			}
			issuerX500Principal = issuerToken.getSubjectX500Principal();
		} catch (Exception e) {
			signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
			signatureValid = false;
		}
		return signatureValid;
	}

	public OCSPRespStatus getResponseStatus() {
		return responseStatus;
	}

	public void setResponseStatus(OCSPRespStatus responseStatus) {
		this.responseStatus = responseStatus;
	}

	public boolean isUseNonce() {
		return useNonce;
	}

	public void setUseNonce(boolean useNonce) {
		this.useNonce = useNonce;
	}

	public boolean isNonceMatch() {
		return nonceMatch;
	}

	public void setNonceMatch(boolean nonceMatch) {
		this.nonceMatch = nonceMatch;
	}

	public BasicOCSPResp getBasicOCSPResp() {
		return basicOCSPResp;
	}

	public void setBasicOCSPResp(BasicOCSPResp basicOCSPResp) {
		this.basicOCSPResp = basicOCSPResp;
	}

	public CertificateID getCertId() {
		return certId;
	}

	public void setCertId(CertificateID certId) {
		this.certId = certId;
	}

	/**
	 * Indicates if the token signature is intact.
	 *
	 * @return {@code true} or {@code false}
	 */
	@Override
	public boolean isValid() {
		return signatureValid;
	}

	/**
	 * This method returns the DSS abbreviation of the certificate. It is used
	 * for debugging purpose.
	 *
	 * @return
	 */
	@Override
	public String getAbbreviation() {
		return "OCSPToken[" + (basicOCSPResp == null ? "?" : DSSUtils.formatInternal(basicOCSPResp.getProducedAt())) + ", signedBy="
				+ (issuerToken == null ? "?" : issuerToken.getDSSIdAsString()) + "]";
	}

	@Override
	public String toString(String indentStr) {
		final StringWriter out = new StringWriter();
		out.append(indentStr).append("OCSPToken[");
		out.append("ProductionTime: ").append(DSSUtils.formatInternal(productionDate)).append("; ");
		out.append("ThisUpdate: ").append(DSSUtils.formatInternal(thisUpdate)).append("; ");
		out.append("NextUpdate: ").append(DSSUtils.formatInternal(nextUpdate)).append('\n');
		out.append("SignedBy: ").append(issuerToken != null ? issuerToken.getDSSIdAsString() : null).append('\n');
		indentStr += "\t";
		out.append(indentStr).append("Signature algorithm: ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm.getJCEId()).append('\n');
		out.append(issuerToken != null ? issuerToken.toString(indentStr) : null).append('\n');
		final List<String> validationExtraInfo = extraInfo.getValidationInfo();
		if (validationExtraInfo.size() > 0) {

			for (final String info : validationExtraInfo) {

				out.append('\n').append(indentStr).append("\t- ").append(info);
			}
			out.append('\n');
		}
		indentStr = indentStr.substring(1);
		out.append(indentStr).append("]");
		return out.toString();
	}

	@Override
	public byte[] getEncoded() {
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

}
