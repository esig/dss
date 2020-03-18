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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.io.StringWriter;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

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
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

/**
 * OCSP Signed Token which encapsulate BasicOCSPResp (BC).
 */
@SuppressWarnings("serial")
public class OCSPToken extends RevocationToken<OCSP> {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPToken.class);

	/**
	 * The encapsulated basic OCSP response.
	 */
	private final BasicOCSPResp basicOCSPResp;
	
	/**
	 * Issuer of the OCSP token
	 */
	private CertificateToken issuerCertificateToken;

	/**
	 * Status of the OCSP response
	 */
	private OCSPRespStatus responseStatus;
	
	/**
	 * The source of embedded into the OCSP token certificates
	 */
	private OCSPCertificateSource certificateSource;

	/**
	 * The default constructor to instantiate an OCSPToken
	 * 
	 * @param ocspResp {@link OCSPResp} containing the response and its status info
	 * @param certificateToken {@link CertificateToken} to which the revocation data is provided for
	 * @param issuerCertificateToken {@link CertificateToken} issued the {@code certificateToken}
	 * @throws OCSPException if an exception occurs
	 */
	public OCSPToken(final OCSPResp ocspResp, final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) throws OCSPException {
		this((BasicOCSPResp) ocspResp.getResponseObject(), certificateToken, issuerCertificateToken);
		this.responseStatus = OCSPRespStatus.fromInt(ocspResp.getStatus());
	}

	/**
	 * The default constructor to instantiate an OCSPToken with BasicOCSPResp only
	 * 
	 * @param basicOCSPResp {@link BasicOCSPResp} containing the response binaries
	 * @param certificateToken {@link CertificateToken} to which the revocation data is provided for
	 * @param issuerCertificateToken {@link CertificateToken} issued the {@code certificateToken}
	 */
	public OCSPToken(final BasicOCSPResp basicOCSPResp, final CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		Objects.requireNonNull(basicOCSPResp, "The OCSP Response must be defined!");
		Objects.requireNonNull(certificateToken, "The related certificate token cannot be null!");
		this.basicOCSPResp = basicOCSPResp;
		this.relatedCertificate = certificateToken;

		SingleResp bestSingleResp = getBestSingleResp(issuerCertificateToken);
		if (bestSingleResp != null) {
			this.thisUpdate = bestSingleResp.getThisUpdate();
			this.nextUpdate = bestSingleResp.getNextUpdate();
			extractStatusInfo(bestSingleResp);
			extractArchiveCutOff(bestSingleResp);
			extractCertHashExtension(bestSingleResp);
		}
		
		checkCertificateValidity(issuerCertificateToken);
	}

	private SingleResp getBestSingleResp(CertificateToken issuerCertificateToken) {
		Date bestUpdate = null;
		SingleResp bestSingleResp = null;
		SingleResp[] responses = getResponses(basicOCSPResp);
		for (final SingleResp singleResp : responses) {
			DigestAlgorithm digestAlgorithm = DSSRevocationUtils.getUsedDigestAlgorithm(singleResp);
			CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(relatedCertificate, issuerCertificateToken, digestAlgorithm);
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

				certHashPresent = true;
				byte[] expectedDigest = relatedCertificate.getDigest(certHash.getAlgorithm());
				byte[] foundDigest = certHash.getValue();
				certHashMatch = Arrays.equals(expectedDigest, foundDigest);

			} catch (Exception e) {
				LOG.warn("Unable to extract id_isismtt_at_certHash : {}", e.getMessage());
			}
		}
	}

	private void checkCertificateValidity(CertificateToken issuerCertificateToken) {
		if (isSignedBy(issuerCertificateToken)) {
			return;
		}
		for (CertificateToken signingCertCandidate : getCertificateSource().getCertificates()) {
			if (isSignedBy(signingCertCandidate)) {
				return;
			}
		}
	}

	@Override
	public Date getProductionDate() {
		if (productionDate == null) {
			productionDate = basicOCSPResp.getProducedAt();
		}
		return productionDate;
	}
	
	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		if (signatureAlgorithm == null) {
			AlgorithmIdentifier signatureAlgorithmID = basicOCSPResp.getSignatureAlgorithmID();
			String oid = signatureAlgorithmID.getAlgorithm().getId();
			byte[] sigAlgParams = signatureAlgorithmID.getParameters() == null ? null : DSSASN1Utils.getDEREncoded(signatureAlgorithmID.getParameters());

			signatureAlgorithm = SignatureAlgorithm.forOidAndParams(oid, sigAlgParams);
		}
		return signatureAlgorithm;
	}
	
	@Override
	public String getRevocationTokenKey() {
		if (revocationTokenKey == null) {
			revocationTokenKey = DSSRevocationUtils.getOcspRevocationKey(relatedCertificate, sourceURL);
		}
		return revocationTokenKey;
	}

	public OCSPRespStatus getResponseStatus() {
		return responseStatus;
	}

	public void setResponseStatus(OCSPRespStatus responseStatus) {
		this.responseStatus = responseStatus;
	}

	public BasicOCSPResp getBasicOCSPResp() {
		return basicOCSPResp;
	}

	@Override
	public OCSPCertificateSource getCertificateSource() {
		if (certificateSource == null) {
			certificateSource = new OCSPCertificateSource(getBasicOCSPResp());
		}
		return certificateSource;
	}

	@Override
	public byte[] getEncoded() {
		return DSSRevocationUtils.getEncodedFromBasicResp(basicOCSPResp);
	}

	@Override
	public X500Principal getIssuerX500Principal() {
		if (issuerCertificateToken != null) {
			return issuerCertificateToken.getSubject().getPrincipal();
		}
		return null;
	}

	@Override
	public CertificateToken getIssuerCertificateToken() {
		return issuerCertificateToken;
	}

	/**
	 * Indicates if the token signature is intact.
	 * NOTE: The method isSignedBy(token) must be called before!
	 *
	 * @return {@code true} or {@code false}
	 */
	@Override
	public boolean isValid() {
		return SignatureValidity.VALID == signatureValidity;
	}
	
	@Override
	public boolean isSignedBy(CertificateToken token) {
		boolean signedBy = super.isSignedBy(token);
		if (signedBy) {
			issuerCertificateToken = token;
		}
		return signedBy;
	}

	@Override
	protected SignatureValidity checkIsSignedBy(final CertificateToken candidate) {
		if (basicOCSPResp == null) {
			return SignatureValidity.INVALID;
		}
		try {
			signatureInvalidityReason = "";
			JcaContentVerifierProviderBuilder jcaContentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
			jcaContentVerifierProviderBuilder.setProvider(DSSSecurityProvider.getSecurityProvider());
			ContentVerifierProvider contentVerifierProvider = jcaContentVerifierProviderBuilder.build(candidate.getPublicKey());
			signatureValidity = SignatureValidity.get(basicOCSPResp.isSignatureValid(contentVerifierProvider));
		} catch (Exception e) {
			LOG.error("An error occurred during in attempt to check signature owner : ", e);
			signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
			signatureValidity = SignatureValidity.INVALID;
		}
		return signatureValidity;
	}

	@Override
	public RevocationType getRevocationType() {
		return RevocationType.OCSP;
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
		out.append(indentStr).append("Id: ").append(getDSSIdAsString()).append('\n');
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

}
