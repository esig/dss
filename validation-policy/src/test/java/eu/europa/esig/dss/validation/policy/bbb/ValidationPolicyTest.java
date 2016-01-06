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

public class ValidationPolicyTest {

	@Test
	public void testBBBWithBasicDiagnosticData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		Assert.assertNotNull(diagnosticData);
		
		BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, diagnosticData.getSignatures().get(0), new Date(), TestPolicyGenerator.generatePolicy(), Context.SIGNATURE);
		
		XmlBasicBuildingBlocks result = bbb.execute();
		
		Assert.assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getConclusion().getSubIndication());
	}
	
	
}
