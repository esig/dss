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
package eu.europa.esig.dss.x509.revocation.ocsp;

import java.io.StringWriter;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSSecurityProvider;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.revocation.RevocationToken;

/**
 * OCSP Signed Token which encapsulate BasicOCSPResp (BC).
 */
@SuppressWarnings("serial")
public class OCSPToken extends RevocationToken {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPToken.class);

	private CertificateID certId;

	private X500Principal issuerX500Principal;

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
		this.revocationType = RevocationType.OCSP;
	}

	@Override
	public void initInfo() {
		if (basicOCSPResp != null) {
			this.productionDate = basicOCSPResp.getProducedAt();

			AlgorithmIdentifier signatureAlgorithmID = basicOCSPResp.getSignatureAlgorithmID();
			String oid = signatureAlgorithmID.getAlgorithm().getId();
			byte[] sigAlgParams = signatureAlgorithmID.getParameters() == null ? null : DSSASN1Utils.getDEREncoded(signatureAlgorithmID.getParameters());

			this.signatureAlgorithm = SignatureAlgorithm.forOidAndParams(oid, sigAlgParams);

			SingleResp bestSingleResp = getBestSingleResp(basicOCSPResp, certId);
			if (bestSingleResp != null) {
				this.thisUpdate = bestSingleResp.getThisUpdate();
				this.nextUpdate = bestSingleResp.getNextUpdate();
				extractStatusInfo(bestSingleResp);
				extractArchiveCutOff(bestSingleResp);
				extractCertHashExtension(bestSingleResp);
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
			LOG.error("Unable to parse the responses object from OCSP", e);
		}
		return responses;
	}

	private void extractStatusInfo(SingleResp bestSingleResp) {
		CertificateStatus certStatus = bestSingleResp.getCertStatus();
		if (CertificateStatus.GOOD == certStatus) {
			if (LOG.isInfoEnabled()) {
				LOG.info("OCSP status is good");
			}
			status = true;
		} else if (certStatus instanceof RevokedStatus) {
			if (LOG.isInfoEnabled()) {
				LOG.info("OCSP status revoked");
			}
			final RevokedStatus revokedStatus = (RevokedStatus) certStatus;
			status = false;
			revocationDate = revokedStatus.getRevocationTime();
			int reasonId = 0; // unspecified
			if (revokedStatus.hasRevocationReason()) {
				reasonId = revokedStatus.getRevocationReason();
			}
			reason = RevocationReason.fromInt(reasonId);
		} else if (certStatus instanceof UnknownStatus) {
			if (LOG.isInfoEnabled()) {
				LOG.info("OCSP status unknown");
			}
			reason = RevocationReason.UNSPECIFIED;
		} else {
			LOG.info("OCSP certificate status: {}", certStatus);
		}
	}

	private void extractArchiveCutOff(SingleResp bestSingleResp) {
		Extension extension = bestSingleResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
		if (extension != null) {
			ASN1GeneralizedTime archiveCutOffAsn1 = (ASN1GeneralizedTime) extension.getParsedValue();
			try {
				archiveCutOff = archiveCutOffAsn1.getDate();
			} catch (ParseException e) {
				LOG.warn("Unable to extract id_pkix_ocsp_archive_cutoff : {}", e.getMessage());
			}
		}
	}

	/**
	 * This method extracts the CertHash extension if present
	 * 
	 * Common PKI Part 4: Operational Protocols
	 * 3.1.2 Common PKI Private OCSP Extensions
	 * 
	 * CertHash ::= SEQUENCE {
	 * hashAlgorithm AlgorithmIdentifier,
	 * certificateHash OCTET STRING }
	 * 
	 * @param bestSingleResp
	 *            the related SingleResponse
	 */
	private void extractCertHashExtension(SingleResp bestSingleResp) {
		Extension extension = bestSingleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
		if (extension != null) {
			try {
				CertHash asn1CertHash = CertHash.getInstance(extension.getParsedValue());
				DigestAlgorithm digestAlgo = DigestAlgorithm.forOID(asn1CertHash.getHashAlgorithm().getAlgorithm().getId());
				Digest certHash = new Digest(digestAlgo, asn1CertHash.getCertificateHash());
				if (certHash != null) {
					certHashPresent = true;
					byte[] expectedDigest = relatedCertificate.getDigest(certHash.getAlgorithm());
					byte[] foundDigest = certHash.getValue();
					certHashMatch = Arrays.equals(expectedDigest, foundDigest);
				}
			} catch (Exception e) {
				LOG.warn("Unable to extract id_isismtt_at_certHash : {}", e.getMessage());
			}
		}
	}

	@Override
	protected boolean checkIsSignedBy(final CertificateToken candidate) {
		if (basicOCSPResp == null) {
			return false;
		}
		try {
			signatureInvalidityReason = "";
			JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
			jcaContentVerifierProviderBuilder.setProvider(DSSSecurityProvider.getSecurityProvider());
			ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(candidate.getPublicKey());
			signatureValid = basicOCSPResp.isSignatureValid(contentVerifierProvider);
		} catch (Exception e) {
			LOG.error("An error occurred during in attempt to check signature owner : ", e);
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

	@Override
	public String getAbbreviation() {
		return "OCSPToken[" + (basicOCSPResp == null ? "?" : DSSUtils.formatInternal(basicOCSPResp.getProducedAt())) + ", signedBy="
				+ getIssuerX500Principal() + "]";
	}

	@Override
	public String toString(String indentStr) {
		final StringWriter out = new StringWriter();
		out.append(indentStr).append("OCSPToken[");
		out.append("ProductionTime: ").append(DSSUtils.formatInternal(productionDate)).append("; ");
		out.append("ThisUpdate: ").append(DSSUtils.formatInternal(thisUpdate)).append("; ");
		out.append("NextUpdate: ").append(DSSUtils.formatInternal(nextUpdate)).append('\n');
		if (getIssuerX500Principal() != null) {
			out.append("SignedBy: ").append(getIssuerX500Principal().toString()).append('\n');
		}
		indentStr += "\t";
		out.append(indentStr).append("Signature algorithm: ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm.getJCEId()).append('\n');
		indentStr = indentStr.substring(1);
		out.append(indentStr).append("]");
		return out.toString();
	}

	@Override
	public byte[] getEncoded() {
		return DSSRevocationUtils.getEncodedFromBasicResp(basicOCSPResp);
	}

	public void setIssuerX500Principal(X500Principal issuerX500Principal) {
		this.issuerX500Principal = issuerX500Principal;
	}

	@Override
	public X500Principal getIssuerX500Principal() {
		return issuerX500Principal;
	}

}
