package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedObject;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class XAdESLTWithKeyInfoReferenceTest {
	
	@Test
	public void test() {
		
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xades-lt-with-keyInfo.xml")));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSignatureIntact());
		
		List<TimestampWrapper> timestampList = signature.getTimestampList();
		assertNotNull(timestampList);
		TimestampWrapper signatureTimestamp = timestampList.get(0);
		List<XmlTimestampedObject> timestampedObjects = signatureTimestamp.getTimestampedObjects();
		assertNotNull(timestampedObjects);
		assertEquals(3, timestampedObjects.size());
		
	}

}
