package eu.europa.esig.dss.jades.validation;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CandidatesForSigningCertificate;
import eu.europa.esig.dss.validation.CertificateValidity;
import eu.europa.esig.dss.validation.SignatureCertificateSource;

public class JAdESCertificateSource extends SignatureCertificateSource {

	private static final long serialVersionUID = -8170607661341382049L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCertificateSource.class);

	private final JWS jws;

	public JAdESCertificateSource(JWS jws) {
		Objects.requireNonNull(jws, "JSON Web signature cannot be null");

		this.jws = jws;

		// signing certificate
		extractX5T();
		extractX5TS256();
		extractX5TO();

		// certificate chain
		extractX5C();
	}

	private void extractX5T() {
		String base64UrlSHA1Certificate = jws.getHeaders()
				.getStringHeaderValue(HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT);
		if (Utils.isStringNotEmpty(base64UrlSHA1Certificate)) {
			Digest digest = new Digest(DigestAlgorithm.SHA1, Base64Url.decode(base64UrlSHA1Certificate));
			LOG.warn("Found {} with value {} but not supported by the JAdES standard",
					HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT, digest);
		}
	}

	private void extractX5TS256() {
		String base64UrlSHA256Certificate = jws.getHeaders()
				.getStringHeaderValue(HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT);
		if (Utils.isStringNotEmpty(base64UrlSHA256Certificate)) {
			CertificateRef certRef = new CertificateRef();
			certRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
			certRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, Base64Url.decode(base64UrlSHA256Certificate)));
			addCertificateRef(certRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
		}
	}

	private void extractX5TO() {
		List<?> x5to = (List<?>) jws.getHeaders().getObjectHeaderValue(JAdESHeaderParameterNames.X5T_O);
		if (Utils.isCollectionNotEmpty(x5to)) {
			for (Object item : x5to) {
				if (item instanceof Map<?,?>) {
					Map<?,?> digestValueAndAlgo = (Map<?,?>) item;

					CertificateRef certRef = new CertificateRef();
					certRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
					certRef.setCertDigest(JAdESUtils.getDigest(digestValueAndAlgo));

					addCertificateRef(certRef, CertificateRefOrigin.SIGNING_CERTIFICATE);
				} else {
					LOG.warn("Unsupported type for {} : {}", JAdESHeaderParameterNames.X5T_O, item.getClass());
				}
			}
		}
	}

	private void extractX5C() {
		List<?> x5c = (List<?>) jws.getHeaders().getObjectHeaderValue(HeaderParameterNames.X509_CERTIFICATE_CHAIN);
		if (Utils.isCollectionNotEmpty(x5c)) {
			for (Object item : x5c) {
				if (item instanceof String) {
					String certificateBase64 = (String) item;
					CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(certificateBase64);
					addCertificate(certificate, CertificateOrigin.KEY_INFO);
				} else {
					LOG.warn("Unsupported type for {} : {}", HeaderParameterNames.X509_CERTIFICATE_CHAIN,
							item.getClass());
				}
			}
		}
	}

	// ------------- Not supported

	@Override
	public List<CertificateToken> getCertificateValues() {
		// Not supported
		return Collections.emptyList();
	}

	@Override
	public List<CertificateToken> getAttrAuthoritiesCertValues() {
		// Not supported
		return Collections.emptyList();
	}

	@Override
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
		// Not supported
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCompleteCertificateRefs() {
		// Not supported
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getAttributeCertificateRefs() {
		// Not supported
		return Collections.emptyList();
	}

	@Override
	protected CandidatesForSigningCertificate extractCandidatesForSigningCertificate(CertificateToken providedSigningCertificateToken) {
		CandidatesForSigningCertificate candidatesForSigningCertificate = new CandidatesForSigningCertificate();

		for (final CertificateToken certificateToken : getKeyInfoCertificates()) {
			candidatesForSigningCertificate.add(new CertificateValidity(certificateToken));
		}

		if (providedSigningCertificateToken != null) {
			candidatesForSigningCertificate.add(new CertificateValidity(providedSigningCertificateToken));
		}

		checkSigningCertificateRef(candidatesForSigningCertificate);

		return candidatesForSigningCertificate;
	}

	public void checkSigningCertificateRef(CandidatesForSigningCertificate candidates) {

		List<CertificateRef> signingCertificateRefs = getSigningCertificateRefs();

		IssuerSerial issuerSerial = getCurrentIssuerSerial();

		if (Utils.isCollectionNotEmpty(signingCertificateRefs)) {
			// must contain only one reference
			final CertificateRef signingCert = signingCertificateRefs.get(0);

			Digest signingCertificateDigest = signingCert.getCertDigest();

			CertificateValidity bestCertificateValidity = null;
			for (CertificateValidity certificateValidity : candidates.getCertificateValidityList()) {
				CertificateToken candidate = certificateValidity.getCertificateToken();

				if (signingCertificateDigest != null) {
					certificateValidity.setDigestPresent(true);

					byte[] candidateDigest = candidate.getDigest(signingCertificateDigest.getAlgorithm());
					if (Arrays.equals(signingCertificateDigest.getValue(), candidateDigest)) {
						certificateValidity.setDigestEqual(true);
					}
				}

				if (issuerSerial != null) {
					certificateValidity.setIssuerSerialPresent(true);

					IssuerSerial candidateIssuerSerial = DSSASN1Utils.getIssuerSerial(candidate);
					if (Objects.equals(issuerSerial.getIssuer(), candidateIssuerSerial.getIssuer())) {
						certificateValidity.setDistinguishedNameEqual(true);
					}

					if (Objects.equals(issuerSerial.getSerial(), candidateIssuerSerial.getSerial())) {
						certificateValidity.setSerialNumberEqual(true);
					}
				}

				if (certificateValidity.isValid()) {
					bestCertificateValidity = certificateValidity;
				}
			}

			// none of them match
			if (bestCertificateValidity == null && !candidates.isEmpty()) {
				bestCertificateValidity = candidates.getCertificateValidityList().iterator().next();
			}

			if (bestCertificateValidity != null) {
				candidates.setTheCertificateValidity(bestCertificateValidity);
			}
		}
	}

	private IssuerSerial getCurrentIssuerSerial() {
		String kid = jws.getKeyIdHeaderValue();
		if (Utils.isStringNotEmpty(kid) && Utils.isBase64Encoded(kid)) {
			byte[] binary = Utils.fromBase64(kid);
			return DSSASN1Utils.getIssuerSerial(binary);
		}
		return null;
	}

}
