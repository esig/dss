package eu.europa.esig.dss.jades.signature;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.datatype.XMLGregorianCalendar;

import org.jose4j.json.internal.json_simple.JSONObject;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.CustomJsonWebSignature;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

/**
 * The class builds a JOSE header according to RFC 7515
 *
 */
public class JOSEHeaderBuilder {
	
	private final CertificateVerifier certificateVerifier;
	private final JAdESSignatureParameters parameters;
	
	/* JSON Signature Object */
	private CustomJsonWebSignature jws = new CustomJsonWebSignature();
	
	/* Contains all critical header names that will be incorporated into the signature */
	private List<String> criticalHeaderNames = new ArrayList<>();
	
	public JOSEHeaderBuilder(final CertificateVerifier certificateVerifier, final JAdESSignatureParameters parameters) {
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
	}
	
	public CustomJsonWebSignature build() {
		// RFC 7515 headers
		incorporateSignatureAlgorithm();
		incorporateCertificateChain();
		
		// EN 119-182 headers
		incorporateSigningTime();
		incorporateSigPlace();
		
		// must be executed the last
		incorporateCritical();
		
		return jws;
	}

	private void incorporateSignatureAlgorithm() {
		jws.setAlgorithmHeaderValue(parameters.getSignatureAlgorithm().getJWAId());
	}
	
	private void incorporateCertificateChain() {
		BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = certificateSelector.getCertificates();
		if (Utils.isCollectionNotEmpty(certificates)) {
			X509Certificate[] x509Certificates = new X509Certificate[certificates.size()];
			for (int ii = 0; ii < certificates.size(); ii++) {
				x509Certificates[ii] = certificates.get(ii).getCertificate();
			}
			jws.setCertificateChainHeaderValue(x509Certificates);
		} else {
			throw new DSSException("Cannot extract a signing certificate chain!");
		}
	}
	
	private void incorporateSigningTime() {
		final Date signingDate = parameters.bLevel().getSigningDate();
		final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
		final String stringSigningTime = xmlGregorianCalendar.toXMLFormat();
		
		addCriticalHeader(JAdESHeaderParameterNames.SIG_T, stringSigningTime);
	}

	private void incorporateSigPlace() {
		Map<String, Object> sigPlaceMap = new HashMap<>();
		sigPlaceMap.put(JAdESHeaderParameterNames.CITY, parameters.bLevel().getSignerLocation().getLocality());
		addCriticalHeader(JAdESHeaderParameterNames.SIG_PL, new JSONObject(sigPlaceMap));
	}
	
	private void incorporateCritical() {
		jws.setCriticalHeaderNames(criticalHeaderNames.toArray(new String[criticalHeaderNames.size()]));
	}
	
	private void addCriticalHeader(String headerName, Object value) {
		jws.getHeaders().setObjectHeaderValue(headerName, value);
		criticalHeaderNames.add(headerName);
	}

}
