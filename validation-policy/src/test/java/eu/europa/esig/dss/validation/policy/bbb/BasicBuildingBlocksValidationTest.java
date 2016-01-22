package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;

public class BasicBuildingBlocksValidationTest extends AbstractValidationPolicy {

	@Test
	public void testBBBWithBasicDiagnosticData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		Assert.assertNotNull(diagnosticData);

		BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, diagnosticData.getSignatures().get(0), new Date(), getPolicy(), Context.SIGNATURE);

		XmlBasicBuildingBlocks result = bbb.execute();

		Assert.assertEquals(Context.SIGNATURE.name(), result.getType());
		Assert.assertNotNull(result.getFC());
		Assert.assertNotNull(result.getISC());
		Assert.assertNotNull(result.getCV());
		Assert.assertNotNull(result.getSAV());
		Assert.assertNotNull(result.getVCI());
		Assert.assertNotNull(result.getXCV());
		Assert.assertEquals(1, result.getISC().getConclusion().getInfo().size());
	}

	@Test
	public void testBBBWithDigestValueOfTheCertificateNotPresent() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithDigestValueOfTheCertificateNotPresent();
		Assert.assertNotNull(diagnosticData);

		BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, diagnosticData.getSignatures().get(0), new Date(), getPolicy(), Context.SIGNATURE);

		XmlBasicBuildingBlocks result = bbb.execute();

		Assert.assertNotNull(result.getISC());
		Assert.assertEquals(Context.SIGNATURE.name(), result.getType());
		Assert.assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, result.getConclusion().getSubIndication());

		Assert.assertNotNull(result.getCV());
		Assert.assertNotNull(result.getSAV());
		Assert.assertNotNull(result.getVCI());
		Assert.assertNotNull(result.getXCV());
	}
}
