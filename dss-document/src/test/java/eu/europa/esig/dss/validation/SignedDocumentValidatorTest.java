package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQualifiers;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlUsedCertificates;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.tsl.KeyUsageCondition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class SignedDocumentValidatorTest {

	private static final String TATA = "TATA";
	private static final String TOTO = "TOTO";
	private static final Logger logger = LoggerFactory.getLogger(SignedDocumentValidatorTest.class);

	@Test
	public void dealCertificateDetails() throws Exception {
		MockDocumentValidator sdv = new MockDocumentValidator();

		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID3DCCAsSgAwIBAgIER/idhzANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFRTEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEPMA0GA1UECxMGRVNURUlEMRcwFQYDVQQDEw5FU1RFSUQtU0sgMjAwNzAeFw0wODA0MDYwOTUzMDlaFw0xMjAzMDUyMjAwMDBaMIGWMQswCQYDVQQGEwJFRTEPMA0GA1UEChMGRVNURUlEMRowGAYDVQQLExFkaWdpdGFsIHNpZ25hdHVyZTEiMCAGA1UEAxMZU0lOSVZFRSxWRUlLTywzNjcwNjAyMDIxMDEQMA4GA1UEBBMHU0lOSVZFRTEOMAwGA1UEKhMFVkVJS08xFDASBgNVBAUTCzM2NzA2MDIwMjEwMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGRN42R9e6VEHMCyvacuubjtm1+5Kk92WgIgtWA8hY8DW2iNvQJ3jOF5XlVIyIDTwl2JVKxWKhXX+8+yNFPpqAK43IINcmMfznw/KcR7jACGNuTrivA9HrvRiqDzTg5E1rktjho6OkDkdV3dgOLB2wyhVm2anNpICfrUq8c09HPwIDMMP5o4HvMIHsMA4GA1UdDwEB/wQEAwIGQDA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL2VzdGVpZDIwMDcuY3JsMFEGA1UdIARKMEgwRgYLKwYBBAHOHwEBAQEwNzASBggrBgEFBQcCAjAGGgRub25lMCEGCCsGAQUFBwIBFhVodHRwOi8vd3d3LnNrLmVlL2Nwcy8wHwYDVR0jBBgwFoAUSAbevoyHV5WAeGP6nCMrK6A6GHUwHQYDVR0OBBYEFJAJUyDrH3rdxTStU+LDa6aHdE8dMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEFBQADggEBAA5qjfeuTdOoEtatiA9hpjDHzyqN1PROcaPrABXGqpLxcHbLVr7xmovILAjxS9fJAw28u9ZE3asRNa9xgQNTeX23mMlojJAYVbYCeIeJ6jtsRiCo34wgvO3CtVfO3+C1T8Du5XLCHa6SoT8SpCApW+Crwe+6eCZDmv2NKTjhn1wCCNO2e8HuSt+pTUNBTUB+rkvF4KO9VnuzRzT7zN7AUdW4OFF3bI+9+VmW3t9vq1zDOxNTdBkCM3zm5TRa8ZtyAPL48bW19JAcYzQLjPGORwoIRNSXdVTqX+cDiw2wbmb2IhPdxRqN9uPwU1x/ltZZ3W5GzJ1t8JeQN7PuGM0OHqE=");

		CertificateToken issuer = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID0zCCArugAwIBAgIERZugDTANBgkqhkiG9w0BAQUFADBdMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUxCzAJBgNVBAYTAkVFMSIwIAYDVQQKExlBUyBTZXJ0aWZpdHNlZXJpbWlza2Vza3VzMRAwDgYDVQQDEwdKdXVyLVNLMB4XDTA3MDEwMzEyMjIzN1oXDTE2MDgyNjE0MjMwMVowWzELMAkGA1UEBhMCRUUxIjAgBgNVBAoTGUFTIFNlcnRpZml0c2VlcmltaXNrZXNrdXMxDzANBgNVBAsTBkVTVEVJRDEXMBUGA1UEAxMORVNURUlELVNLIDIwMDcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWp2jLCsA7K9AxoPDOL0geM1GoR0Q6wSUICCJYyFkUMboEMxpSzFB6tlb0ySlHEU6Fs+tjA4QrSqwaw0uNk4BXv1lkoOr6DUc+20+AQd5jB6A0atrltZ1XG5IvDEep3DJPykkk2MPxUz7dZx7XUEr/kdUWI9cDIkFWic7y9oTBY9JaV6lxm08kweZ/qTw5PU8/bTvZCE0ygvBXU4TDS2FpUJ/+jTzM2ocWa3QjFQv2Sir6LBvgNY3du/m+WLABq0dgN18R4nhFtmaVepqAeUuEi8eRBl6yLTSmMwYCY46LsK5CdjTCZSZv934FtNuyY6Ph9nCXJAgNAY+GfNJfdMXAgMBAAGjgZwwgZkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAf4wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5zay5lZS9jcmxzL2p1dXIvY3JsLmNybDAfBgNVHSMEGDAWgBQEqnpHo+SJrxrPCkCnGD9v7+l9vjAdBgNVHQ4EFgQUSAbevoyHV5WAeGP6nCMrK6A6GHUwDQYJKoZIhvcNAQEFBQADggEBACO6SJrjN5WZuiLSMy/tSmT/w3dd/KPErSAdUIJYkC7hOIauW7jZ3VNgNUMHSIkUoP8AviEMjGA4lkT61YScpJAdmgl8Y80HFdZV5CsThhddoIdZ3cZjSI4NZmTVkSduTjoySALxKL3ZEIPrepQDvNEeV1WSpI5+u/vMekUWJSPc8BK9O2av1e9ResKyPJidqrIksHFjNS+Yt8Ouw7F10MHaPPzMiwoa0DYTVsIKJncPTQmvdJG8M0DDToiiNPQuUy5d1CA75Wtjs+yILGZXpOfbdoQhE7G4pbZaF1s69jKp+zc0ZT4g2OoKfI2TiIX9qeGJMxkOENcd1DDqYVfePmo=");

		ServiceInfo serviceInfo = new ServiceInfo();
		Condition condition = new KeyUsageCondition(KeyUsageBit.nonRepudiation, true);
		serviceInfo.addQualifierAndCondition(TOTO, condition);

		Condition condition2 = new KeyUsageCondition(KeyUsageBit.crlSign, true);
		serviceInfo.addQualifierAndCondition(TATA, condition2);
		assertNotNull(serviceInfo);

		issuer.addSourceType(CertificateSourceType.TRUSTED_LIST);
		issuer.addServiceInfo(serviceInfo);

		assertTrue(certificate.isSignedBy(issuer));

		Method method = SignedDocumentValidator.class.getDeclaredMethod("dealCertificateDetails", Set.class, CertificateToken.class);
		method.setAccessible(true);
		XmlCertificate cert = (XmlCertificate) method.invoke(sdv, new HashSet<Object>(), certificate);
		assertNotNull(cert);

		Method methodDealTrustedService = SignedDocumentValidator.class.getDeclaredMethod("dealTrustedService", CertificateToken.class, XmlCertificate.class);
		methodDealTrustedService.setAccessible(true);
		methodDealTrustedService.invoke(sdv, certificate, cert);

		List<XmlTrustedServiceProviderType> trustedServiceProviders = cert.getTrustedServiceProvider();
		assertTrue(CollectionUtils.isNotEmpty(trustedServiceProviders));

		boolean foundTOTO = false;
		boolean foundTATA = false;
		for (XmlTrustedServiceProviderType xmlTrustedServiceProviderType : trustedServiceProviders) {
			XmlQualifiers qualifiers = xmlTrustedServiceProviderType.getQualifiers();
			assertNotNull(qualifiers);
			for (String qualifier : qualifiers.getQualifier()) {
				if (TOTO.equals(qualifier)) {
					foundTOTO = true;
				} else if (TATA.equals(qualifier)) {
					foundTATA = true;
				}
			}
		}
		assertTrue(foundTOTO);
		assertFalse(foundTATA);

		DiagnosticData dd = new DiagnosticData();
		XmlUsedCertificates value = new XmlUsedCertificates();
		value.getCertificate().add(cert);
		dd.setUsedCertificates(value);

		logger.info(getJAXBObjectAsString(dd, eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData.class.getPackage().getName()));
	}

	private String getJAXBObjectAsString(Object obj, String contextPath) {
		try {
			JAXBContext context = JAXBContext.newInstance(contextPath);
			Marshaller marshaller = context.createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			StringWriter writer = new StringWriter();
			marshaller.marshal(obj, writer);
			return writer.toString();
		} catch (JAXBException e) {
			logger.error("Unable to generate string value for context " + contextPath + " (code:" + e.getErrorCode() + ") : " + e.getMessage(), e);
			return null;
		}
	}

}
