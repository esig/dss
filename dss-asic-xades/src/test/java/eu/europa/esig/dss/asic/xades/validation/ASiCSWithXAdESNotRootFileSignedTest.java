package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;

public class ASiCSWithXAdESNotRootFileSignedTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/no-root-signed-file.asics");
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		XmlBasicBuildingBlocks bbb = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		assertNotNull(bbb);
		
		XmlFC fc = bbb.getFC();
		assertNotNull(fc);
		assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
		assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());
		
		for (XmlConstraint xmlConstraint : fc.getConstraint()) {
			if (MessageTag.BBB_FC_ISFP_ASICS.getId().equals(xmlConstraint.getName().getNameId())) {
				assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
				assertEquals(MessageTag.BBB_FC_ISFP_ASICS_ANS.getId(), xmlConstraint.getError().getNameId());
			} else {
				assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
			}
		}
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);
		
		List<String> contentFiles = diagnosticData.getContainerInfo().getContentFiles();
		assertEquals(1, contentFiles.size());
		
		String fileName = contentFiles.get(0);
		assertEquals("hello/sample.xml", fileName);
	}

}
