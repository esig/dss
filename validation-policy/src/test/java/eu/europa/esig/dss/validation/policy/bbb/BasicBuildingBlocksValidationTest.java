package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.EN319102.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;

public class BasicBuildingBlocksValidationTest {

	@Test
	public void testBBBWithBasicDiagnosticData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		Assert.assertNotNull(diagnosticData);
		
		BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, diagnosticData.getSignatures().get(0), new Date(), TestPolicyGenerator.generatePolicy(), Context.SIGNATURE);
		
		XmlBasicBuildingBlocks result = bbb.execute();
		
		Assert.assertEquals(Indication.VALID, result.getConclusion().getIndication());
		Assert.assertEquals(Context.SIGNATURE.name(), result.getType());
		Assert.assertNotNull(result.getISC());
		Assert.assertNotNull(result.getCV());
		Assert.assertNotNull(result.getSAV());
		Assert.assertNotNull(result.getVCI());
		Assert.assertNotNull(result.getXCV());
	}
	
	@Test
	public void testBBBWithDigestValueOfTheCertificateNotPresent() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithDigestValueOfTheCertificateNotPresent();
		Assert.assertNotNull(diagnosticData);
		
		BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, diagnosticData.getSignatures().get(0), new Date(), TestPolicyGenerator.generatePolicy(), Context.SIGNATURE);
		
		XmlBasicBuildingBlocks result = bbb.execute();
		
		Assert.assertNotNull(result.getISC());
		Assert.assertEquals(Context.SIGNATURE.name(), result.getType());
		Assert.assertEquals(Indication.INVALID, result.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.FORMAT_FAILURE, result.getConclusion().getSubIndication());
		
		Assert.assertNull(result.getCV());
		Assert.assertNull(result.getSAV());
		Assert.assertNull(result.getVCI());
		Assert.assertNull(result.getXCV());
	}
}
