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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.security.DSSContentVerifierProviderSecurityFactory;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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
	 * The used SingleResp (can be null)
	 */
	private final SingleResp latestSingleResp;

	/**
	 * Issuer of the OCSP token
	 */
	private CertificateToken issuerCertificateToken;

	
	/**
	 * The source of embedded into the OCSP token certificates
	 */
	private OCSPCertificateSource certificateSource;

	/**
	 * The default constructor to instantiate an OCSPToken with BasicOCSPResp only
	 * 
	 * @param basicOCSPResp    {@link BasicOCSPResp} containing the response
	 *                         binaries
	 * @param latestSingleResp {@link SingleResp} to be used with the current
	 *                         certificate
	 * @param certificate      {@link CertificateToken} to which the revocation data
	 *                         is provided for
	 * @param issuer           {@link CertificateToken} issued the
	 *                         {@code certificateToken}
	 */
	public OCSPToken(final BasicOCSPResp basicOCSPResp, final SingleResp latestSingleResp, final CertificateToken certificate, CertificateToken issuer) {
		Objects.requireNonNull(basicOCSPResp, "The OCSP Response must be defined!");
		Objects.requireNonNull(certificate, "The related certificate token cannot be null!");
		this.basicOCSPResp = basicOCSPResp;
		this.productionDate = basicOCSPResp.getProducedAt();
		this.relatedCertificate = certificate;
		this.latestSingleResp = latestSingleResp;

		if (latestSingleResp != null) {
			this.thisUpdate = latestSingleResp.getThisUpdate();
			this.nextUpdate = latestSingleResp.getNextUpdate();
			extractStatusInfo(latestSingleResp);
			extractArchiveCutOff(latestSingleResp);
			extractCertHashExtension(latestSingleResp);
		}
		
		checkSignatureValidity(issuer);
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("OCSPToken created : {})", getDSSIdAsString());
		}
	}

	private void extractStatusInfo(SingleResp bestSingleResp) {
		org.bouncycastle.cert.ocsp.CertificateStatus certStatus = bestSingleResp.getCertStatus();
		if (org.bouncycastle.cert.ocsp.CertificateStatus.GOOD == certStatus) {
			if (LOG.isInfoEnabled()) {
				LOG.info("OCSP status is good");
			}
			status = CertificateStatus.GOOD;
		} else if (certStatus instanceof RevokedStatus) {
			if (LOG.isInfoEnabled()) {
				LOG.info("OCSP status revoked");
			}
			final RevokedStatus revokedStatus = (RevokedStatus) certStatus;
			status = CertificateStatus.REVOKED;
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
			status = CertificateStatus.UNKNOWN;
		} else {
			LOG.info("OCSP certificate status: {}", certStatus);
		}
	}

	private void extractArchiveCutOff(SingleResp bestSingleResp) {
		Extension extension = bestSingleResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
		if (extension != null) {
			try {
				ASN1GeneralizedTime archiveCutOffAsn1 = (ASN1GeneralizedTime) extension.getParsedValue();
				archiveCutOff = archiveCutOffAsn1.getDate();

			} catch (Exception e) {
				String errorMessage = "Unable to extract id_pkix_ocsp_archive_cutoff : {}";
				if (LOG.isDebugEnabled()) {
					LOG.warn(errorMessage, e.getMessage(), e);
				} else {
					LOG.warn(errorMessage, e.getMessage());
				}
			}
		}
	}

	/**
	 * This method extracts the CertHash extension if present
	 * <p>
	 * Common PKI Part 4: Operational Protocols
	 * 3.1.2 Common PKI Private OCSP Extensions
	 * <p>
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
				String errorMessage = "Unable to extract id_isismtt_at_certHash : {}";
				if (LOG.isDebugEnabled()) {
					LOG.warn(errorMessage, e.getMessage(), e);
				} else {
					LOG.warn(errorMessage, e.getMessage());
				}
			}
		}
	}

	private void checkSignatureValidity(CertificateToken caCertificateToken) {
		CandidatesForSigningCertificate candidates = getCertificateSource().getCandidatesForSigningCertificate(caCertificateToken);
		
		SignatureIntegrityValidator signingCertificateValidator = new OCSPSignatureIntegrityValidator(this);
		CertificateValidity certificateValidity = signingCertificateValidator.validate(candidates);
		if (certificateValidity != null) {
			candidates.setTheCertificateValidity(certificateValidity);

			this.issuerCertificateToken = certificateValidity.getCertificateToken();
		}
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

	/**
	 * Returns the {@code BasicOCSPResp}
	 *
	 * @return {@link BasicOCSPResp}
	 */
	public BasicOCSPResp getBasicOCSPResp() {
		return basicOCSPResp;
	}

	/**
	 * Returns the latest single response
	 *
	 * @return {@link SingleResp}
	 */
	public SingleResp getLatestSingleResp() {
		return latestSingleResp;
	}

	@Override
	public OCSPCertificateSource getCertificateSource() {
		if (certificateSource == null) {
			certificateSource = new OCSPCertificateSource(getBasicOCSPResp());
		}
		return certificateSource;
	}

	@Override
	public List<CertificateToken> getCertificates() {
		return getCertificateSource().getCertificates();
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
	 * Indicates if the OCSP token is valid.
	 * NOTE: The method isSignedBy(token) must be called before!
	 *
	 * @return whether the OCSP token is valid
	 */
	@Override
	public boolean isValid() {
		return isSignatureIntact() && isOCSPVersionValid();
	}
	
	/**
	 * Verifies if the current OCSP token has been signed by the specified publicKey
	 * @param publicKey {@link PublicKey} of a signing candidate
	 * 
	 * @return {@link SignatureValidity}
	 */
	@Override
	protected SignatureValidity checkIsSignedBy(final PublicKey publicKey) {
		try {
			signatureInvalidityReason = "";
			ContentVerifierProvider contentVerifierProvider = DSSContentVerifierProviderSecurityFactory.INSTANCE.build(publicKey);
			signatureValidity = SignatureValidity.get(basicOCSPResp.isSignatureValid(contentVerifierProvider));
		} catch (Exception e) {
			LOG.warn("An error occurred during in attempt to check signature owner : ", e);
			signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
			signatureValidity = SignatureValidity.INVALID;
		}
		return signatureValidity;
	}

	/**
	 * This method returns version defined within the OCSP token (returns version value + 1, i.e. 'v1' for value '0').
	 * Returns '1' if no version defined (default value).
	 *
	 * @return version from the basic OCSP response
	 */
	public int getOCSPTokenVersion() {
		return basicOCSPResp.getVersion();
	}

	/**
	 * This method verifies whether the basic OCSP response contains the valid version of the response syntax,
	 * which MUST be v1 (value is 0) (see RFC 6960).
	 *
	 * @return TRUE if the basic OCSP response version is v1 (value 0) or not defined, FALSE otherwise
	 */
	private boolean isOCSPVersionValid() {
		boolean versionValid = getOCSPTokenVersion() == 1;
		if (!versionValid && Utils.isStringEmpty(signatureInvalidityReason)) {
			signatureInvalidityReason = "Basic OCSP Response version is invalid (shall be v1)!";
		}
		return versionValid;
	}

	@Override
	public RevocationType getRevocationType() {
		return RevocationType.OCSP;
	}

	@Override
	public String getAbbreviation() {
		return "OCSPToken[" + (basicOCSPResp == null ? "?" : DSSUtils.formatDateToRFC(basicOCSPResp.getProducedAt())) + ", signedBy="
				+ getIssuerX500Principal() + "]";
	}

	@Override
	public String toString(String indentStr) {
		final StringBuilder out = new StringBuilder();
		out.append(indentStr).append("OCSPToken[\n");
		indentStr += "\t";
		out.append(indentStr).append("Id: ").append(getDSSIdAsString()).append('\n');
		out.append(indentStr).append("ProductionTime: ").append(DSSUtils.formatDateToRFC(productionDate)).append("; ");
		out.append(indentStr).append("ThisUpdate: ").append(DSSUtils.formatDateToRFC(thisUpdate)).append("; ");
		out.append(indentStr).append("NextUpdate: ").append(DSSUtils.formatDateToRFC(nextUpdate)).append('\n');
		if (getIssuerX500Principal() != null) {
			out.append(indentStr).append("SignedBy: ").append(getIssuerX500Principal().toString()).append('\n');
		}
		out.append(indentStr).append("Signature algorithm: ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm.getJCEId()).append('\n');
		if (getRelatedCertificateId() != null) {
			out.append(indentStr).append("Related certificate: ").append(getRelatedCertificateId()).append('\n');
		}
		indentStr = indentStr.substring(1);
		out.append(indentStr).append("]");
		return out.toString();
	}

}
