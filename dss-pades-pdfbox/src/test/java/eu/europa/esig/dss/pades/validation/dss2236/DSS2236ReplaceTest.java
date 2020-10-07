package eu.europa.esig.dss.pades.validation.dss2236;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlModificationDetection;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;

public class DSS2236ReplaceTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-2236/replace.pdf"));
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		super.checkPdfRevision(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		
		XmlModificationDetection modificationDetection = pdfRevision.getModificationDetection();
		assertNotNull(modificationDetection);
		
		List<XmlModification> visualDifferences = modificationDetection.getVisualDifference();
		assertEquals(1, visualDifferences.size());
		assertEquals(1, visualDifferences.get(0).getPage().intValue());
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isSigningCertificateIdentified());
	}

}
