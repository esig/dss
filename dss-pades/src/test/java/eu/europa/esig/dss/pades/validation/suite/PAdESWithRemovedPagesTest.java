package eu.europa.esig.dss.pades.validation.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;

public class PAdESWithRemovedPagesTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-removed-pages.pdf"));
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(2, signature.getPdfPageDifferenceConcernedPages().size());
		assertTrue(signature.getPdfPageDifferenceConcernedPages().contains(BigInteger.valueOf(2)));
		assertTrue(signature.getPdfPageDifferenceConcernedPages().contains(BigInteger.valueOf(3)));
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		I18nProvider i18nProvider = new I18nProvider();
		assertTrue(simpleReport.getErrors(simpleReport.getFirstSignatureId()).contains(
				i18nProvider.getMessage(MessageTag.BBB_FC_DSFREAP_ANS)));		
	}

}
