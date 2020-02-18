package eu.europa.esig.dss.jades.validation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwx.HeaderParameterNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateRef;
import eu.europa.esig.dss.validation.SignatureCertificateSource;

public class JAdESCertificateSource extends SignatureCertificateSource {

	private static final long serialVersionUID = -8170607661341382049L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCertificateSource.class);

	private final CustomJsonWebSignature jws;

	private List<CertificateRef> signingCertificates;
	private List<CertificateToken> certificateChain;

	public JAdESCertificateSource(CustomJsonWebSignature jws, CertificatePool certPool) {
		super(certPool);
		Objects.requireNonNull(jws, "JSON Web signature cannot be null");

		this.jws = jws;

		// singing certificate
		getSigningCertificateValues();

		// certificate chain
		getKeyInfoCertificates();
	}

	@Override
	public List<CertificateRef> getSigningCertificateValues() {
		if (signingCertificates != null) {
			return signingCertificates;
		}

		signingCertificates = new ArrayList<>();

		extractX5T();
		extractX5TS256();
		extractX5TO();

		return signingCertificates;
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
			certRef.setCertDigest(new Digest(DigestAlgorithm.SHA256, Base64Url.decode(base64UrlSHA256Certificate)));
			signingCertificates.add(certRef);
		}
	}

	private void extractX5TO() {
		JSONArray x5to = (JSONArray) jws.getHeaders().getObjectHeaderValue(JAdESHeaderParameterNames.X5T_O);
		if (Utils.isCollectionNotEmpty(x5to)) {
			for (Object item : x5to) {
				if (item instanceof JSONObject) {
					JSONObject digestValueAndAlgo = (JSONObject) item;

					CertificateRef certRef = new CertificateRef();
					certRef.setCertDigest(getDigest(digestValueAndAlgo));

					signingCertificates.add(certRef);
				} else {
					LOG.warn("Unsupported type for {} : {}", JAdESHeaderParameterNames.X5T_O, item.getClass());
				}
			}
		}
	}

	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		if (certificateChain != null) {
			return certificateChain;
		}

		certificateChain = new ArrayList<>();

		extractX5C();

		return certificateChain;
	}

	private void extractX5C() {
		JSONArray x5c = (JSONArray) jws.getHeaders().getObjectHeaderValue(HeaderParameterNames.X509_CERTIFICATE_CHAIN);
		if (Utils.isCollectionNotEmpty(x5c)) {
			for (Object item : x5c) {
				if (item instanceof String) {
					String certificateBase64 = (String) item;

					CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(certificateBase64);
					certificateChain.add(addCertificate(certificate));
				} else {
					LOG.warn("Unsupported type for {} : {}", HeaderParameterNames.X509_CERTIFICATE_CHAIN,
							item.getClass());
				}
			}
		}
	}

	private Digest getDigest(JSONObject digestValueAndAlgo) {
		String digestAlgoURI = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_ALG);
		String digestValueBase64 = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_VAL);
		return new Digest(DigestAlgorithm.forXML(digestAlgoURI), Utils.fromBase64(digestValueBase64));
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

}
