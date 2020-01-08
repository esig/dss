/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.snippets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.Arrays;

import javax.xml.bind.JAXBContext;
import javax.xml.transform.Templates;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.DetailedReportXmlDefiner;
import eu.europa.esig.dss.detailedreport.jaxb.ObjectFactory;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class SignedDocumentValidatorTest {

	@Test
	public void test() throws Exception {

		DSSDocument document = new FileDocument(new File("src/test/resources/signedXmlXadesLT.xml"));

		// tag::demo[]
		
		// The method allows instantiation of a related validator for a provided document 
		// independently on its format (the target dss module must be added as dependency)
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		
		// Allows specifying a custom certificate verifier (online or offline)
		documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

		// Allows defining of a signing certificate in the explicit way, in case if the certificate
		// is not provided in the signature itself (can be used for non-ASiC signatures)
		documentValidator.defineSigningCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIC9TCCAd2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADArMQswCQYDVQQGEwJBQTEMMAoGA1UEChMDRFNTMQ4wDAYDVQQDEwVJQ0EgQTAeFw0xMzEyMDIxNzMzMTBaFw0xNTEyMDIxNzMzMTBaMDAxCzAJBgNVBAYTAkFBMQwwCgYDVQQKEwNEU1MxEzARBgNVBAMTCnVzZXIgQSBSU0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJUHHAphmSDdQ1t62tppK+dLTANsE2nAj+HCpasS3ohlBsrhteRsvTAbrDyIzCmTYWu/nVI4TGvbzBESwV/QitlkoMLpYFw32MIBf2DLmECzGJ3vm5haw6u8S9quR1h8Vu7QWd+5KMabZuR+j91RiSuoY0xS2ZQxJw1vhvW9hRYjAgMBAAGjgaIwgZ8wCQYDVR0TBAIwADAdBgNVHQ4EFgQU9ESnTWfwg13c3LQZzqqwibY5WVYwUwYDVR0jBEwwSoAUIO1CDsBSUcEoFZxKaWf1PAL1U+uhL6QtMCsxDDAKBgNVBAoTA0RTUzELMAkGA1UEBhMCQUExDjAMBgNVBAMTBVJDQSBBggEBMAsGA1UdDwQEAwIHgDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEFBQADggEBAGnhhnoyVUhDnr/BSbZ/uWfSuwzFPG+2V9K6WxdIaaXOORFGIdFwGlAwA/Qzpq9snfBxuTkAykxq0uEDhHTj0qXxWRjQ+Dop/DrmccoF/zDvgGusyY1YXaABd/kc3IYt7ns7z3tpiqIz4A7a/UHplBRXfqjyaZurZuJQRaSdxh6CNhdEUiUBxkbb1SdMjuOgjzSDjcDjcegjvDquMKdDetvtu2Qh4ConBBo3fUImwiFRWnbudS5H2HE18ikC7gY/QIuNr7USf1PNyUgcG2g31cMtemj7UTBHZ2V/jPf7ZXqwfnVSaYkNvM3weAI6R3PI0STjdxN6a9qjt9xld40YEdw="));
		
		
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
		documentValidator.setEnableEtsiValidationReport(true);
		
		// Executes the validation process and produces validation reports:
		// Simple report, Detailed report, Diagnostic data and ETSI Validation Report (if enabled)
		Reports reports = documentValidator.validateDocument();
		
		// Returns ETSI Validation Report (if enabled, NULL otherwise)
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();

		// end::demo[]
		
		assertNotNull(etsiValidationReport);

		// tag::demo-facade[]
		Reports completeReports = documentValidator.validateDocument();
		
		DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();

		// Transforms the JAXB object to String (xml content)
		String marshalledDetailedReport = detailedReportFacade.marshall(completeReports.getDetailedReportJaxb());

		// Transforms the String (xml content) to a JAXB Object
		XmlDetailedReport xmlDetailedReport = detailedReportFacade.unmarshall(marshalledDetailedReport);

		// Generates the HTML content for the given Detailed Report (compatible with
		// BootStrap)
		// Similar method is available for PDF generation (requires Apache FOP)
		String htmlDetailedReport = detailedReportFacade.generateHtmlReport(completeReports.getDetailedReportJaxb());

		// end::demo-facade[]
		assertNotNull(xmlDetailedReport);
		assertNotNull(htmlDetailedReport);

		// tag::demo-xml-definer[]

		// The JAXB Object Factory
		ObjectFactory objectFactory = DetailedReportXmlDefiner.OBJECT_FACTORY;

		// The JAXBContext (cached)
		JAXBContext jaxbContext = DetailedReportXmlDefiner.getJAXBContext();

		// The XML Schema to validate a XML content (cached)
		Schema schema = DetailedReportXmlDefiner.getSchema();

		// The Templates object with the loaded XML Stylesheet to generate the HTML
		// content from the JAXB Object (cached)
		Templates bootstrap3Templates = DetailedReportXmlDefiner.getHtmlBootstrap3Templates();

		// The Templates object with the loaded XML Stylesheet to generate the PDF
		// content from the JAXB Object (cached)
		Templates pdfTemplates = DetailedReportXmlDefiner.getPdfTemplates();

		// end::demo-xml-definer[]
		assertNotNull(objectFactory);
		assertNotNull(jaxbContext);
		assertNotNull(schema);
		assertNotNull(bootstrap3Templates);
		assertNotNull(pdfTemplates);
	}

}
