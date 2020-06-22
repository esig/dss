package eu.europa.esig.dss.cookbook.example.validate;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class XAdES132OnlyTest {

	@Test
	public void test() {

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		FileDocument xmlDocument = new FileDocument("src/test/resources/signature-pool/signedXmlXadesB.xml");

		// tag::demo[]
		XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(xmlDocument);
		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);

		// Restrict the current XMLDocumentValidator to XAdES 1.3.2 (and 1.4.1 for
		// archival timestamps)
		List<XAdESPaths> xadesPathsHolders = xmlDocumentValidator.getXAdESPathsHolder();
		xadesPathsHolders.clear();
		xadesPathsHolders.add(new XAdES132Paths());

		Reports reports = xmlDocumentValidator.validateDocument();
		// end::demo[]

		assertNotNull(reports);

	}

}
