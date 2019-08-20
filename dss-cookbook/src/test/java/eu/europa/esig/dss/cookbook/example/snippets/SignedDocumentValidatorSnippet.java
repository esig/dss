package eu.europa.esig.dss.cookbook.example.snippets;

import java.io.File;
import java.util.Arrays;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class SignedDocumentValidatorSnippet {

	public static void main(String[] args) {

		DSSDocument document = new FileDocument(new File("src/test/resources/signedXmlXadesLT.xml"));

		// tag::demo[]
		
		// The method allows instantiation of a related validator for a provided document 
		// independently on its format (the target dss module must be added as dependency)
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		
		// Allows defining of a signing certificate in the explicit way, in case if the certificate
		// is not provided in the signature itself (can be used for non-ASiC signatures)
		documentValidator.defineSigningCertificate(DSSUtils.loadCertificate("certificate.cer"));
		
		// Allows specifying a custom certificate verifier (online or offline)
		documentValidator.setCertificateVerifier(new CommonCertificateVerifier());
		
		// Sets the detached contents that were used for the detached signature creation
		documentValidator.setDetachedContents(Arrays.asList(new InMemoryDocument("Hello world!".getBytes())));
		
		// Allows defining a custom Process Executor
		// By default used {@code new DefaultSignatureProcessExecutor()}
		documentValidator.setProcessExecutor(new DefaultSignatureProcessExecutor());
		
		// Sets custom Signature Policy Provider
		documentValidator.setSignaturePolicyProvider(new SignaturePolicyProvider());
		
		// Sets an expected signature validation level
		// The recommended level is ARCHIVAL_DATA (maximal level of the validation)
		// Default : ValidationLevel.ARCHIVAL_DATA
		documentValidator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		
		// Sets if the ETSI validation report must be created 
		// If true, it will become accessible through the method below
		// Default : true
		documentValidator.setEnableEtsiValidationReport(false);
		
		// Executes the validation process and produces validation reports:
		// Simple report, Detailed report, Diagnostic data and ETSI Validation Report (if enabled)
		Reports reports = documentValidator.validateDocument();
		
		// Returns ETSI Validation Report (if enabled, NULL otherwise)
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();

		// end::demo[]
		
	}

}
