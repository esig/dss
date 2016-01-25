package integration;

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.SoapDocumentValidationService;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.dto.DataToValidateDTO;
import eu.europa.esig.dss.validation.reports.dto.ReportsDTO;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "/test-context.xml")
public class SoapDocumentValidationTest {
	
	@Autowired
	private SoapDocumentValidationService validationService;
	
	@Test
	public void testWithNoPolicyAndNoOriginalFile() {
		RemoteDocument signedFile = new RemoteDocument(new FileDocument("src/test/resources/XAdESLTA.xml"));
		
		DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, null, null);
		
		ReportsDTO result = validationService.validateSignature(toValidate);
		
		Assert.assertNotNull(result.getDiagnosticData());
		Assert.assertNotNull(result.getDetailedReport());
		Assert.assertNotNull(result.getSimpleReport());
		
		Assert.assertEquals(1, result.getSimpleReport().getSignature().size());
		Assert.assertEquals(2, result.getDiagnosticData().getSignature().get(0).getTimestamps().getTimestamp().size());
		Assert.assertTrue(result.getSimpleReport().getSignature().get(0).getIndication().equals(Indication.VALID));
		
		Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport());
		reports.print();
	}

	@Test
	public void testWithNoPolicyAndOriginalFile() {
		RemoteDocument signedFile = new RemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalFile =  new RemoteDocument(new FileDocument("src/test/resources/sample.xml"));
		
		DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, null);
		
		ReportsDTO result = validationService.validateSignature(toValidate);
		
		Assert.assertNotNull(result.getDiagnosticData());
		Assert.assertNotNull(result.getDetailedReport());
		Assert.assertNotNull(result.getSimpleReport());
		
		Assert.assertEquals(1, result.getSimpleReport().getSignature().size());
		Assert.assertTrue(result.getSimpleReport().getSignature().get(0).getIndication().equals(Indication.INDETERMINATE));
		
		Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport());
		reports.print();
	}
	
	@Test
	public void testWithPolicyAndOriginalFile() throws Exception {
		RemoteDocument signedFile = new RemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		RemoteDocument originalFile =  new RemoteDocument(new FileDocument("src/test/resources/sample.xml"));
		
		JAXBContext context = JAXBContext.newInstance(ConstraintsParameters.class.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		InputStream stream = new FileInputStream("src/test/resources/constraint.xml");
		ConstraintsParameters policy = (ConstraintsParameters) unmarshaller.unmarshal(stream);
		
		DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, originalFile, policy);
		
		ReportsDTO result = validationService.validateSignature(toValidate);
		
		Assert.assertNotNull(result.getDiagnosticData());
		Assert.assertNotNull(result.getDetailedReport());
		Assert.assertNotNull(result.getSimpleReport());
		
		Assert.assertEquals(1, result.getSimpleReport().getSignature().size());
		Assert.assertTrue(result.getSimpleReport().getSignature().get(0).getIndication().equals(Indication.INVALID));
		
		Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport());
		reports.print();
	}
	
	@Test
	public void testWithPolicyAndNoOriginalFile() throws Exception {
		RemoteDocument signedFile = new RemoteDocument(new FileDocument("src/test/resources/xades-detached.xml"));
		
		JAXBContext context = JAXBContext.newInstance(ConstraintsParameters.class.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		InputStream stream = new FileInputStream("src/test/resources/constraint.xml");
		ConstraintsParameters policy = (ConstraintsParameters) unmarshaller.unmarshal(stream);
		
		DataToValidateDTO toValidate = new DataToValidateDTO(signedFile, null, policy);
		
		ReportsDTO result = validationService.validateSignature(toValidate);
		
		Assert.assertNotNull(result.getDiagnosticData());
		Assert.assertNotNull(result.getDetailedReport());
		Assert.assertNotNull(result.getSimpleReport());
		
		Assert.assertEquals(1, result.getSimpleReport().getSignature().size());
		Assert.assertTrue(result.getSimpleReport().getSignature().get(0).getIndication().equals(Indication.INDETERMINATE));
		
		Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport());
		reports.print();
	}
}
