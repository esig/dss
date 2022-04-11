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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Extracts and stores certificates from a JAdES signature
 */
public class JAdESCertificateSource extends SignatureCertificateSource {

	private static final long serialVersionUID = -8170607661341382049L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCertificateSource.class);

	/** The JWS Signature to extract certificates from */
	private final transient JWS jws;

	/** Represents the unsigned 'etsiU' header */
	private final transient JAdESEtsiUHeader etsiUHeader;

	/**
	 * Default constructor
	 *
	 * @param jws {@link JWS} signature
	 * @param etsiUHeader {@link JAdESEtsiUHeader} unsigned component
	 */
	public JAdESCertificateSource(JWS jws, JAdESEtsiUHeader etsiUHeader) {
		Objects.requireNonNull(jws, "JSON Web signature cannot be null");
		Objects.requireNonNull(etsiUHeader, "etsiUHeader cannot be null");

		this.jws = jws;
		this.etsiUHeader = etsiUHeader;

		// signing certificate
		extractX5T();
		extractX5TS256();
		extractX5TO();
		extractSigX5Ts();
		extractKid();

		// certificate chain
		extractX5C();

		// unsigned properties
		extractEtsiU();
	}

	/**
	 * Retrieves the list of {@link CertificateRef}s referenced within a 'kid' (key identifier) header
	 *
	 * @return the list of references to the signing certificate (from key identifier)
	 */
	public List<CertificateRef> getKeyIdentifierCertificateRefs() {
		return getCertificateRefsByOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
	}

	/**
	 * Retrieves the Set of {@link CertificateToken}s according to a reference present
	 * within a 'kid' (key identifier) header
	 *
	 * @return Set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getKeyIdentifierCertificates() {
		return findTokensFromRefs(getKeyIdentifierCertificateRefs());
	}

	private void extractX5T() {
		String base64UrlSHA1Certificate = jws.getProtectedHeaderValueAsString(
				HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT);
		if (Utils.isStringNotEmpty(base64UrlSHA1Certificate)) {
			Digest digest = new Digest(DigestAlgorithm.SHA1, DSSJsonUtils.fromBase64Url(base64UrlSHA1Certificate));
			LOG.warn("Found {} with value {} but not supported by the JAdES standard",
					HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT, digest);
		}
	}

	private void extractX5TS256() {
		String base64UrlSHA256Certificate = jws.getProtectedHeaderValueAsString(
				HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT);
		if (Utils.isStringNotEmpty(base64UrlSHA256Certificate)) {
			CertificateRef certRef = new CertificateRef();
			certRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, DSSJsonUtils.fromBase64Url(base64UrlSHA256Certificate)));
			addCertificateRef(certRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
		}
	}

	private void extractX5TO() {
		extractX5TO(jws.getProtectedHeaderValueAsMap(JAdESHeaderParameterNames.X5T_O));
	}

	private void extractX5TO(Map<?, ?> x5TO) {
		if (Utils.isMapNotEmpty(x5TO)) {
			Digest digest = DSSJsonUtils.getDigest(x5TO);
			if (digest != null) {
				CertificateRef certRef = new CertificateRef();
				certRef.setCertDigest(digest);
				addCertificateRef(certRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
			}
		}
	}

	private void extractSigX5Ts() {
		List<?> sigX5tsList = jws.getProtectedHeaderValueAsList(JAdESHeaderParameterNames.SIG_X5T_S);
		if (Utils.isCollectionNotEmpty(sigX5tsList)) {
			for (Object item : sigX5tsList) {
				extractX5TO(DSSJsonUtils.toMap(item, JAdESHeaderParameterNames.X5T_O));
			}
		}
	}

	private void extractKid() {
		IssuerSerial kidIssuerSerial = getKidIssuerSerial();
		if (kidIssuerSerial != null) {
			CertificateRef certificateRef = new CertificateRef();
			certificateRef.setCertificateIdentifier(DSSASN1Utils.toSignerIdentifier(kidIssuerSerial));
			addCertificateRef(certificateRef, CertificateRefOrigin.KEY_IDENTIFIER);
		}
	}

	private void extractX5C() {
		List<?> x509CertChain = jws.getProtectedHeaderValueAsList(HeaderParameterNames.X509_CERTIFICATE_CHAIN);
		if (Utils.isCollectionNotEmpty(x509CertChain)) {
			for (Object item : x509CertChain) {
				String certificateBase64 = DSSJsonUtils.toString(item);
				CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(certificateBase64);
				addCertificate(certificate, CertificateOrigin.KEY_INFO);
			}
		}
	}

	private void extractEtsiU() {
		if (!etsiUHeader.isExist()) {
			return;
		}

		for (JAdESAttribute attribute : etsiUHeader.getAttributes()) {
			extractCertificateValues(attribute);
			extractAttrAuthoritiesCertValues(attribute);
			extractTimestampValidationData(attribute);

			extractCompleteCertificateRefs(attribute);
			extractAttributeCertificateRefs(attribute);
		}
	}

	private void extractCertificateValues(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.X_VALS.equals(attribute.getHeaderName())) {
			extractCertificateValues(DSSJsonUtils.toList(attribute.getValue(), JAdESHeaderParameterNames.X_VALS),
					CertificateOrigin.CERTIFICATE_VALUES);
		}
	}

	private void extractAttrAuthoritiesCertValues(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.AX_VALS.equals(attribute.getHeaderName())) {
			extractCertificateValues(DSSJsonUtils.toList(attribute.getValue(), JAdESHeaderParameterNames.AX_VALS),
					CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES);
		}
	}

	private void extractTimestampValidationData(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.TST_VD.equals(attribute.getHeaderName())) {
			Map<?,?> tstVd = DSSJsonUtils.toMap(attribute.getValue(), JAdESHeaderParameterNames.TST_VD);
			List<?> xVals = DSSJsonUtils.getAsList(tstVd, JAdESHeaderParameterNames.X_VALS);
			if (Utils.isCollectionNotEmpty(xVals)) {
				extractCertificateValues(xVals, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
			}
		}
	}

	private void extractCompleteCertificateRefs(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.X_REFS.equals(attribute.getHeaderName())) {
			extractCertificateRefs(DSSJsonUtils.toList(attribute.getValue(), JAdESHeaderParameterNames.X_REFS),
					CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
		}
	}

	private void extractAttributeCertificateRefs(JAdESAttribute attribute) {
		if (JAdESHeaderParameterNames.AX_REFS.equals(attribute.getHeaderName())) {
			extractCertificateRefs(DSSJsonUtils.toList(attribute.getValue(), JAdESHeaderParameterNames.AX_REFS),
					CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
		}
	}

	private void extractCertificateValues(List<?> xVals, CertificateOrigin origin) {
		for (Object item : xVals) {
			Map<?, ?> xVal = DSSJsonUtils.toMap(item);
			Map<?, ?> x509Cert = DSSJsonUtils.getAsMap(xVal, JAdESHeaderParameterNames.X509_CERT);
			Map<?, ?> otherCert = DSSJsonUtils.getAsMap(xVal, JAdESHeaderParameterNames.OTHER_CERT);
			if (Utils.isMapNotEmpty(x509Cert)) {
				extractX509Cert(x509Cert, origin);
			} else if (Utils.isMapNotEmpty(otherCert)) {
				LOG.warn("The header '{}' is not supported! The entry is skipped.", JAdESHeaderParameterNames.OTHER_CERT);
			}
		}
	}

	private void extractCertificateRefs(List<?> xRefs, CertificateRefOrigin origin) {
		for (Object item : xRefs) {
			Map<?, ?> xref = DSSJsonUtils.toMap(item);
			CertificateRef certificateRef = JAdESCertificateRefExtractionUtils.createCertificateRef(xref);
			if (certificateRef != null) {
				addCertificateRef(certificateRef, origin);
			}
		}
	}

	private void extractX509Cert(Map<?, ?> x509Cert, CertificateOrigin origin) {
		String encoding = DSSJsonUtils.getAsString(x509Cert, JAdESHeaderParameterNames.ENCODING);
		if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
			String val = DSSJsonUtils.getAsString(x509Cert, JAdESHeaderParameterNames.VAL);
			if (Utils.isStringNotBlank(val)) {
				addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(val), origin);
			}

		} else {
			LOG.warn("Unsupported encoding header value : '{}'", encoding);
		}
	}

	@Override
	protected CandidatesForSigningCertificate extractCandidatesForSigningCertificate(
			CertificateSource signingCertificateSource) {

		CandidatesForSigningCertificate candidatesForSigningCertificate = new CandidatesForSigningCertificate();

		for (final CertificateToken certificateToken : getKeyInfoCertificates()) {
			candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
		}

		if (signingCertificateSource != null) {
			resolveFromSource(signingCertificateSource, candidatesForSigningCertificate);
		}

		// From JWK (not JAdES)
		PublicKey publicKey = extractPublicKey();
		if (publicKey != null) {
			candidatesForSigningCertificate.add(new CertificateValidity(publicKey));
		}

		checkSigningCertificateRef(candidatesForSigningCertificate);

		return candidatesForSigningCertificate;
	}

	private void resolveFromSource(CertificateSource signingCertificateSource, CandidatesForSigningCertificate candidatesForSigningCertificate) {
		if (Utils.isStringNotEmpty(jws.getKeyIdHeaderValue())) {
			if (signingCertificateSource instanceof KidCertificateSource) {
				KidCertificateSource kidCertificateSource = (KidCertificateSource) signingCertificateSource;
				CertificateToken externalCandidate = kidCertificateSource.getCertificateByKid(jws.getKeyIdHeaderValue());
				if (externalCandidate != null) {
					LOG.debug("Resolved certificate by kid");
					candidatesForSigningCertificate.add(new CertificateValidity(externalCandidate));
					return;
				}
			} else {
				LOG.warn("JWS/JAdES contains a kid (provide a KidCertificateSource to resolve it)");
			}
		}

		Digest certificateDigest = getSigningCertificateDigest();
		if (certificateDigest != null) {
			Set<CertificateToken> certificatesByDigest = signingCertificateSource.getByCertificateDigest(certificateDigest);
			if (Utils.isCollectionNotEmpty(certificatesByDigest)) {
				LOG.debug("Resolved certificate by digest");
				for (CertificateToken certificateToken : certificatesByDigest) {
					candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
				}
			}
		} else if (candidatesForSigningCertificate.isEmpty()) {
			List<CertificateToken> certificates = signingCertificateSource.getCertificates();
			LOG.debug("No signing certificate reference found. " +
					"Resolve all {} certificates from the provided certificate source as signing candidates.", certificates.size());
			for (CertificateToken certCandidate : certificates) {
				candidatesForSigningCertificate.add(new CertificateValidity(certCandidate));
			}
		}
	}

	private PublicKey extractPublicKey() {
		try {
			PublicJsonWebKey jwkHeader = jws.getJwkHeader();
			if (jwkHeader != null) {
				return jwkHeader.getPublicKey();
			}
		} catch (Exception e) {
			LOG.warn("Unable to extract the public key", e);
		}
		return null;
	}

	private void checkSigningCertificateRef(CandidatesForSigningCertificate candidates) {
		CertificateRef signingCertRef = null;
		final List<CertificateRef> potentialSigningCertificates = getSigningCertificateRefs();
		if (Utils.isCollectionNotEmpty(potentialSigningCertificates)) {
			// first reference shall be a reference to a signing certificate
			signingCertRef = potentialSigningCertificates.get(0);
		}

		CertificateRef kidCertRef = null;
		final List<CertificateRef> keyIdentifierCertificateRefs = getKeyIdentifierCertificateRefs();
		if (Utils.isCollectionNotEmpty(keyIdentifierCertificateRefs)) {
			kidCertRef = keyIdentifierCertificateRefs.get(0);
		}

		if (signingCertRef != null) {
			CertificateValidity bestCertificateValidity = null;
			// check all certificates against the signingCert ref and find the best one
			final List<CertificateValidity> certificateValidityList = candidates.getCertificateValidityList();
			for (final CertificateValidity certificateValidity : certificateValidityList) {
				if (isValid(certificateValidity, signingCertRef, kidCertRef)) {
					bestCertificateValidity = certificateValidity;
				}
			}
			if (bestCertificateValidity != null) {
				candidates.setTheCertificateValidity(bestCertificateValidity);
			}
		}
	}

	private boolean isValid(CertificateValidity certificateValidity,
							CertificateRef signingCertRef, CertificateRef kidCertRef) {
		certificateValidity.setDigestPresent(signingCertRef != null && signingCertRef.getCertDigest() != null);
		certificateValidity.setIssuerSerialPresent(kidCertRef != null && kidCertRef.getCertificateIdentifier() != null);

		CertificateToken certificateToken = certificateValidity.getCertificateToken();
		if (certificateToken != null) {
			if (signingCertRef != null) {
				certificateValidity.setDigestEqual(certificateMatcher.matchByDigest(certificateToken, signingCertRef));
			}
			if (kidCertRef != null) {
				certificateValidity.setSerialNumberEqual(certificateMatcher.matchBySerialNumber(certificateToken, kidCertRef));
				certificateValidity.setDistinguishedNameEqual(certificateMatcher.matchByIssuerName(certificateToken, kidCertRef));
			}
		}
		return certificateValidity.isValid();
	}

	private Digest getSigningCertificateDigest() {
		List<CertificateRef> signingCertificateRefs = getSigningCertificateRefs();
		if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
			// must contain only one reference
			final CertificateRef signingCert = signingCertificateRefs.get(0);
			return signingCert.getCertDigest();
		}
		return null;
	}

	private IssuerSerial getKidIssuerSerial() {
		return DSSJsonUtils.getIssuerSerial(jws.getKeyIdHeaderValue());
	}

}
