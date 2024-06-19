package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultDocumentAnalyzerTest {

    @Test
    public void test() throws Exception {

        // tag::demo[]
        
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.model.InMemoryDocument;
        // import eu.europa.esig.dss.model.x509.CertificateToken;
        // import eu.europa.esig.dss.spi.signature.AdvancedSignature;
        // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
        // import eu.europa.esig.dss.spi.validation.ValidationContext;
        // import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
        // import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
        // import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
        // import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
        // import eu.europa.esig.dss.utils.Utils;
        // import java.util.Collections;
        // import java.util.Set;
        
        // Load a document to read
        DSSDocument document = new FileDocument("src/test/resources/signature-pool/signedXmlXadesLT.xml");

        // The method allows instantiation of a related DocumentAnalyzer for a provided document 
        // independently on its format (the target dss module must be added as dependency)
        DocumentAnalyzer documentAnalyzer = DefaultDocumentAnalyzer.fromDocument(document);

        // Allows specifying a custom certificate verifier (online or offline)
        documentAnalyzer.setCertificateVerifier(new CommonCertificateVerifier());

        // Sets the detached contents that were used for the detached signature creation
        documentAnalyzer.setDetachedContents(Collections.singletonList(new InMemoryDocument("Hello world!".getBytes())));

        // Executes the validation process and returns a ValidationContext object,
        // containing the validated tokens
        ValidationContext validationContext = documentAnalyzer.validate();

        // It is possible to extract validated tokens in a form of JAVA objects
        Set<AdvancedSignature> processedSignatures = validationContext.getProcessedSignatures();
        Set<TimestampToken> processedTimestamps = validationContext.getProcessedTimestamps();
        Set<CertificateToken> processedCertificates = validationContext.getProcessedCertificates();
        Set<RevocationToken<?>> processedRevocations = validationContext.getProcessedRevocations();
        // end::demo[]
        
        assertEquals(1, Utils.collectionSize(processedSignatures));
        assertEquals(1, Utils.collectionSize(processedTimestamps));
        assertEquals(4, Utils.collectionSize(processedCertificates));
        assertEquals(0, Utils.collectionSize(processedRevocations));
        
    }

}
