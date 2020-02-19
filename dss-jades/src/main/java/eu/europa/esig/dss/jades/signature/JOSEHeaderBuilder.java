package eu.europa.esig.dss.jades.signature;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.datatype.XMLGregorianCalendar;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.validation.CustomJsonWebSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * The class builds a JOSE header according to EN 119-182
 *
 */
public class JOSEHeaderBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JOSEHeaderBuilder.class);
	
	private final CertificateVerifier certificateVerifier;
	private final JAdESSignatureParameters parameters;
	private final DSSDocument signingDocument;
	
	/* JSON Signature Object */
	protected CustomJsonWebSignature jws = new CustomJsonWebSignature();
	
	/* Contains all critical header names that will be incorporated into the signature */
	private List<String> criticalHeaderNames = new ArrayList<>();
	
	public JOSEHeaderBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters, final DSSDocument signingDocument) {
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
		this.signingDocument = signingDocument;
	}
	
	public CustomJsonWebSignature build() {
		// RFC 7515 headers
		incorporateSignatureAlgorithm();
		incorporateContentType();
		incorporateKeyIdentifier();
		incorporateSigningCertificateUri();
		incorporateSigningCertificate();
		incorporateCertificateChain();
		
		// EN 119-182 headers
		incorporateSigningTime();
		incorporateSignatureProductionPlace();
		
		// must be executed the last
		incorporateCritical();
		
		return jws;
	}

	/**
	 * Incorporates 5.1.2 The alg (X.509 URL) header parameter
	 */
	private void incorporateSignatureAlgorithm() {
		jws.setAlgorithmHeaderValue(parameters.getSignatureAlgorithm().getJWAId());
	}

	/**
	 * Incorporates 5.1.3 The cty (content type) header parameter
	 */
	private void incorporateContentType() {
		if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {
			// not applicable for detached signatures (see EN 119-182 ch.5.1.3)
			return;
		}
		MimeType mimeType = signingDocument.getMimeType();
		if (mimeType != null) {
			jws.setContentTypeHeaderValue(mimeType.getMimeTypeString());
		}
	}

	/**
	 * Incorporates 5.1.4 The kid (key identifier) header parameter
	 */
	protected void incorporateKeyIdentifier() {
		if (parameters.getSigningCertificate() == null) {
			return;
		}
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(parameters.getSigningCertificate());
		String issuerBase64 = Utils.toBase64(DSSASN1Utils.getDEREncoded(issuerSerial));
		jws.setKeyIdHeaderValue(issuerBase64);
	}

	/**
	 * Incorporates 5.1.5 The x5u (X.509 URL) header parameter
	 */
	protected void incorporateSigningCertificateUri() {
		// not supported
	}
	
	/**
	 * Incorporates 5.1.7 The x5t#S256 (X.509 Certificate SHA-256 Thumbprint) header parameter
	 * or 5.2.2	The x5t#o (X509 certificate digest) header parameter
	 */
	protected void incorporateSigningCertificate() {
		if (parameters.getSigningCertificate() == null) {
			return;
		}
		
		DigestAlgorithm signingCertificateDigestMethod = parameters.getSigningCertificateDigestMethod();
		if (DigestAlgorithm.SHA256.equals(signingCertificateDigestMethod)) {
			incorporateSiginingCertificateSha256Thumbprint(parameters.getSigningCertificate());
			
		} else {
			List<CertificateToken> certificates = Arrays.asList(parameters.getSigningCertificate());
			incorporateSigningCertificateOtherDigestReferences(certificates, signingCertificateDigestMethod);
		}
	}

	
	/**
	 * Incorporates 5.1.7 The x5t#S256 (X.509 Certificate SHA-256 Thumbprint) header parameter
	 */
	protected void incorporateSiginingCertificateSha256Thumbprint(CertificateToken signingCertificate) {
		jws.setX509CertSha256ThumbprintHeaderValue(signingCertificate.getCertificate());
	}

	/**
	 * Incorporates 5.2.2 The x5t#o (X509 certificate digest) header parameter
	 */
	protected void incorporateSigningCertificateOtherDigestReferences(List<CertificateToken> certificates, DigestAlgorithm digestAlgorithm) {
		List<JSONObject> digAndValues = new ArrayList<>();
		for (CertificateToken certificateToken : certificates) {
			byte[] digestValue = certificateToken.getDigest(digestAlgorithm);
			JSONObject digAndVal = JAdESUtils.getDigAndValObject(digestValue, digestAlgorithm);
			digAndValues.add(digAndVal);
		}
		addCriticalHeader(JAdESHeaderParameterNames.X5T_O, new JSONArray(digAndValues));
	}
	
	/**
	 * Incorporates 5.1.8 The x5c (X.509 Certificate Chain) header parameter
	 */
	protected void incorporateCertificateChain() {
		if (!parameters.isIncludeCertificateChain() || parameters.getSigningCertificate() == null) {
			return;
		}
		
		BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = certificateSelector.getCertificates();
		
		X509Certificate[] x509Certificates = new X509Certificate[certificates.size()];
		for (int ii = 0; ii < certificates.size(); ii++) {
			x509Certificates[ii] = certificates.get(ii).getCertificate();
		}
		jws.setCertificateChainHeaderValue(x509Certificates);
	}
	
	/**
	 * Incorporates 5.2.1 The sigT (claimed signing time) header parameter
	 */
	private void incorporateSigningTime() {
		final Date signingDate = parameters.bLevel().getSigningDate();
		final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
		final String stringSigningTime = xmlGregorianCalendar.toXMLFormat();
		
		addCriticalHeader(JAdESHeaderParameterNames.SIG_T, stringSigningTime);
	}

	/**
	 * Incorporates 5.2.4 The sigPl (signature production place) header parameter
	 */
	private void incorporateSignatureProductionPlace() {
		SignerLocation signerProductionPlace = parameters.bLevel().getSignerLocation();
		if (signerProductionPlace != null) {
			
			String city = signerProductionPlace.getLocality();
			String streetAddress = signerProductionPlace.getStreet();
			String stateOrProvince = signerProductionPlace.getStateOrProvince();
			String postalCode = signerProductionPlace.getPostalCode();
			String country = signerProductionPlace.getCountry();
			
			// sigPlace must have at least one property
			if (Utils.isAtLeastOneStringNotEmpty(city, streetAddress, stateOrProvince, postalCode, country)) {
				Map<String, Object> sigPlaceMap = new HashMap<>();
				
				if (city != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.CITY, city);
				}
				if (streetAddress != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.STR_ADDR, streetAddress);
				}
				if (stateOrProvince != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.STAT_PROV, stateOrProvince);
				}
				if (postalCode != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.POST_CODE, postalCode);
				}
				if (country != null) {
					sigPlaceMap.put(JAdESHeaderParameterNames.COUNTRY, country);
				}
				
				addCriticalHeader(JAdESHeaderParameterNames.SIG_PL, new JSONObject(sigPlaceMap));
				
			} else {
				LOG.warn("SignerLocation is defined, but does not contain any properties! 'SigPlace' attribute requires at least one property!");
				
			}
		}
	}
	
	/**
	 * Incorporates 5.1.9 The crit (critical) header parameter
	 */
	private void incorporateCritical() {
		jws.setCriticalHeaderNames(criticalHeaderNames.toArray(new String[criticalHeaderNames.size()]));
	}
	
	/**
	 * Adds a new critical header property
	 * 
	 * @param headerName {@link String} name of a header to incorporate
	 * @param value of the header property
	 */
	protected void addCriticalHeader(String headerName, Object value) {
		jws.getHeaders().setObjectHeaderValue(headerName, value);
		criticalHeaderNames.add(headerName);
	}

}
