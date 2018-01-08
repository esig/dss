package eu.europa.esig.dss.validation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.ws.Endpoint;
import javax.xml.ws.Service;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
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
	public void testReadCertificatesFromSoapValidation() throws IOException, CertificateException, SAXException, JAXBException {
		File sampleFile = new File("../dss-pades/src/test/resources/validation/hello_signed_INCSAVE_signed.pdf");
		byte[] signedDocument = Files.readAllBytes(Paths.get(sampleFile.toURI()));
		WSReportsDTO wsReportsDTO = docValidation.validateSignature(new DataToValidateDTO(new RemoteDocument(signedDocument, null, null), null, null));

		Assert.assertNotNull(wsReportsDTO);
		
		// Forcing JAXB unmarshall call manually
		DiagnosticData diagnosticData = null;
		try (InputStream schemaStream = getClass().getResourceAsStream("/xsd/DiagnosticData.xsd")) {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema = sf.newSchema(new StreamSource(schemaStream));
	
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			JAXBContext jaxbContext = JAXBContext.newInstance(DiagnosticData.class);
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.setSchema(schema);
			marshaller.marshal(wsReportsDTO.getDiagnosticData(), baos);
			
			Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			unmarshaller.setSchema(schema);
			diagnosticData = (DiagnosticData) unmarshaller.unmarshal(new ByteArrayInputStream(baos.toByteArray()));
		}

		Assert.assertNotNull(diagnosticData);
		Assert.assertNotNull(diagnosticData.getUsedCertificates());
		Assert.assertFalse(diagnosticData.getUsedCertificates().isEmpty());
		for (XmlCertificate xmlCertificate : diagnosticData.getUsedCertificates()) {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			try (ByteArrayInputStream bais = new ByteArrayInputStream(xmlCertificate.getBase64Encoded())) {
				Certificate certificate = certificateFactory.generateCertificate(bais);
				Assert.assertNotNull(certificate);
			}
		}
	}
}
