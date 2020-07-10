package eu.europa.esig.dss.jades.validation;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.PKIEncoding;
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

	private transient final JWS jws;

	public JAdESCertificateSource(JWS jws) {
		Objects.requireNonNull(jws, "JSON Web signature cannot be null");

		this.jws = jws;

		// signing certificate
		extractX5T();
		extractX5TS256();
		extractX5TO();

		// certificate chain
		extractX5C();

		// unsigned properties
		extractEtsiU();
	}

	private void extractX5T() {
		String base64UrlSHA1Certificate = jws.getHeaders()
				.getStringHeaderValue(HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT);
		if (Utils.isStringNotEmpty(base64UrlSHA1Certificate)) {
			Digest digest = new Digest(DigestAlgorithm.SHA1, JAdESUtils.fromBase64Url(base64UrlSHA1Certificate));
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
			certRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, JAdESUtils.fromBase64Url(base64UrlSHA256Certificate)));
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

	private void extractEtsiU() {
		List<?> etsiU = JAdESUtils.getEtsiU(jws);
		if (Utils.isCollectionEmpty(etsiU)) {
			return;
		}

		for (Object item : etsiU) {
			if (item instanceof Map) {
				Map<?, ?> jsonObject = (Map<?, ?>) item;
				
				List<?> xVals = (List<?>) jsonObject.get(JAdESHeaderParameterNames.X_VALS);
				if (Utils.isCollectionNotEmpty(xVals)) {
					extractCertificateValues(xVals, CertificateOrigin.CERTIFICATE_VALUES);
				}
				
				List<?> axVals = (List<?>) jsonObject.get(JAdESHeaderParameterNames.AX_VALS);
				if (Utils.isCollectionNotEmpty(axVals)) {
					extractCertificateValues(axVals, CertificateOrigin.ATTR_AUTORITIES_CERT_VALUES);
				}

				List<?> xRefs = (List<?>) jsonObject.get(JAdESHeaderParameterNames.X_REFS);
				if (Utils.isCollectionNotEmpty(xRefs)) {
					extractCertificateRefs(xRefs, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS);
				}

				List<?> axRefs = (List<?>) jsonObject.get(JAdESHeaderParameterNames.AX_REFS);
				if (Utils.isCollectionNotEmpty(axRefs)) {
					extractCertificateRefs(axRefs, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS);
				}
			}
		}
	}

	private void extractCertificateValues(List<?> xVals, CertificateOrigin origin) {
		for (Object item : xVals) {
			if (item instanceof Map) {
				Map<?, ?> xVal = (Map<?, ?>) item;
				Map<?, ?> x509Cert = (Map<?, ?>) xVal.get(JAdESHeaderParameterNames.X509_CERT);
				Map<?, ?> otherCert = (Map<?, ?>) xVal.get(JAdESHeaderParameterNames.OTHER_CERT);
				if (x509Cert != null) {
					extractX509Cert(x509Cert, origin);
				} else if (otherCert != null) {
					LOG.warn("Unsupported otherCert found");
				}
			}
		}
	}

	private void extractCertificateRefs(List<?> xRefs, CertificateRefOrigin origin) {
		for (Object item : xRefs) {
			if (item instanceof Map) {
				CertificateRef certificateRef = JAdESCertificateRefExtractionUtils.createCertificateRef((Map<?, ?>) item);
				if (certificateRef != null) {
					addCertificateRef(certificateRef, origin);
				}
			}
		}
	}

	private void extractX509Cert(Map<?, ?> x509Cert, CertificateOrigin origin) {
		String encoding = (String) x509Cert.get(JAdESHeaderParameterNames.ENCODING);
		if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
			String certDerBase64 = (String) x509Cert.get(JAdESHeaderParameterNames.VAL);
			addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(certDerBase64),
					origin);
		} else {
			LOG.warn("Unsupported encoding '{}'", encoding);
		}
	}

	// ------------- Not supported

	@Override
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
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

		// From JWK (not JAdES)
		PublicKey publicKey = extractPublicKey();
		if (publicKey != null) {
			candidatesForSigningCertificate.add(new CertificateValidity(publicKey));
		}

		checkSigningCertificateRef(candidatesForSigningCertificate);

		return candidatesForSigningCertificate;
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
		return JAdESUtils.getIssuerSerial(jws.getKeyIdHeaderValue());
	}

}
