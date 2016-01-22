package integration;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.validation.RestDocumentValidationService;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.report.dto.ValidationResultDTO;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "/test-context.xml")
public class RestDocumentValidationTest {

	@Autowired
	private RestDocumentValidationService validationService;
	
	@Test
	public void testWithNoPolicyAndNoOriginalFile() {
		RemoteDocument signedFile = new RemoteDocument(new FileDocument("src/test/resources/XAdESLTA.xml"));
		
		ValidationResultDTO result = validationService.validateSignature(signedFile, null, null);
		
		Assert.assertNotNull(result.getDiagnosticData());
		Assert.assertNotNull(result.getDetailedReport());
		Assert.assertNotNull(result.getSimpleReport());
		
		Assert.assertEquals(1, result.getSimpleReport().getSignature().size());
		Assert.assertEquals(2, result.getDiagnosticData().getSignature().get(0).getTimestamps().getTimestamp().size());
		Assert.assertTrue(result.getSimpleReport().getSignature().get(0).getIndication().equals(Indication.VALID));
	}
}
