package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import javax.xml.bind.JAXBElement;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class MultipleCounterSignatureValidationTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/signedFile.pdf.p7s");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(6, signatures.size()); // 3 sig + 3 counter-sig

		int nbSig = 0;
		int nbCounter = 0;
		int nbCounterOfCounter = 0;
		for (SignatureWrapper signatureWrapper : signatures) {
			if (signatureWrapper.isCounterSignature()) {
				nbCounter++;

				SignatureWrapper parent = signatureWrapper.getParent();
				assertNotNull(parent);
				if (parent.isCounterSignature()) {
					nbCounterOfCounter++;
				}

			} else {
				nbSig++;
			}
		}
		assertEquals(3, nbSig);
		assertEquals(3, nbCounter);
		assertEquals(1, nbCounterOfCounter);
	}
	
	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		super.verifyETSIValidationReport(etsiValidationReportJaxb);
		
		List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
		assertEquals(6, signatureValidationReports.size());
		
		int nbCounterSig = 0;
		for (SignatureValidationReportType signatureValidationReportType : signatureValidationReports) {
			SignatureAttributesType signatureAttributes = signatureValidationReportType.getSignatureAttributes();
			List<Object> signingTimeOrSigningCertificateOrDataObjectFormat = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
			for (Object attribute : signingTimeOrSigningCertificateOrDataObjectFormat) {
				if (attribute instanceof JAXBElement) {
					JAXBElement e = (JAXBElement) attribute;
					if (e.getDeclaredType().equals(SACounterSignatureType.class)) {
						nbCounterSig++;
					}
				}
			}
		}
		assertEquals(3, nbCounterSig);
	}
	
}
