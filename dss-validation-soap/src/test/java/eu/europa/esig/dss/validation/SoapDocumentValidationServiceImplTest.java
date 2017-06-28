package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.xml.namespace.QName;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Service;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;

public class SoapDocumentValidationServiceImplTest {

	private Endpoint endpoint;
	private SoapDocumentValidationService docValidation;
	
	@Before
	public void setupEnvironment() throws MalformedURLException {
		RemoteDocumentValidationService validationService = new RemoteDocumentValidationService();
		validationService.setVerifier(new CommonCertificateVerifier());
		
		SoapDocumentValidationServiceImpl serviceImpl = new SoapDocumentValidationServiceImpl();
		serviceImpl.setValidationService(validationService);
		
		String serviceUri = "http://localhost:18080/api/soap/ValidationService";
		endpoint = Endpoint.publish(serviceUri, serviceImpl);
		
	    String namespaceURI = "http://validation.dss.esig.europa.eu/";
	    String servicePart = "DocumentValidationService";
	    QName serviceQN = new QName(namespaceURI, servicePart);

	    Service service = Service.create(new URL(serviceUri+"?wsdl"), serviceQN);

	    String portName = "soap";
	    QName portQN = new QName(namespaceURI, portName);
	 
	    docValidation = service.getPort(portQN, SoapDocumentValidationService.class);
	}
	
	@After
	public void tearDownEnvironment() {
		if (endpoint != null)
			endpoint.stop();
	}
	
	@Test
	public void testReadCertificatesFromSoapValidation() throws IOException, CertificateException {
		File sampleFile = new File("../dss-pades/src/test/resources/sample.pdf");
		byte[] signedDocument = Files.readAllBytes(Paths.get(sampleFile.toURI()));
		WSReportsDTO wsReportsDTO = docValidation.validateSignature(new DataToValidateDTO(new RemoteDocument(signedDocument, null, null), null, null));
		Assert.assertNotNull(wsReportsDTO);
		for (XmlCertificate certificate : wsReportsDTO.getDiagnosticData().getUsedCertificates()) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			try (ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getBase64Encoded())) {
				certificateFactory.generateCertificate(bais);
			}
		}
	}
}
