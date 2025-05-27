package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContainerEvidenceRecordParameters;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ERAdditionSnippet {

    @Test
    void embedERTest() {

        DSSDocument signatureDocument = new FileDocument("src/test/resources/snippets/X-B-LT.xml");
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/snippets/evidence-record-X-B-LT.xml");
        List<DSSDocument> detachedDocuments = Collections.emptyList();

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

        // tag::add-er[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.spi.validation.CertificateVerifier;
        // import eu.europa.esig.dss.xades.definition.XAdESNamespace;
        // import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
        // import eu.europa.esig.dss.xades.signature.XAdESService;

        // Create a XAdESService to be used to add an existing evidence record to a signature
        // NOTE: CertificateVerifier may provide an additional configuration for validation
        //       of evidence record and its timestamps
        XAdESService xadesService = new XAdESService(certificateVerifier);

        // Configure the Evidence Record incorporation parameters
        XAdESEvidenceRecordIncorporationParameters parameters = new XAdESEvidenceRecordIncorporationParameters();

        // Set Id of the signature to be extended with the evidence record
        // NOTE: the parameter can be omitted for documents containing a single signature.
        parameters.setSignatureId("id-270f7c0b892f5ad2a1178a20b68d101a");

        // Provide original documents in case of a detached signature
        parameters.setDetachedContents(detachedDocuments);

        // This property allows setting of whether the new evidence record covers
        // the whole signature file, or only the content covered by the latest existing
        // evidence record.
        // When set to FALSE, a new unsigned property will be created to incorporate the evidence record.
        // When set to TRUE, the evidence record will be added within the latest existing
        // unsigned property containing an evidence record, when present.
        // Default : FALSE (evidence record is included within a new unsigned property)
        parameters.setParallelEvidenceRecord(false);

        // (XAdES only) Allows setting of a custom namespace definition for
        // the SealingEvidenceRecords unsigned attribute.
        // Default : xadesen:http://uri.etsi.org/19132/v1.1.1#
        parameters.setXadesERNamespace(XAdESNamespace.XADES_EVIDENCERECORD_NAMESPACE);

        // Add the evidence record within a signature document using the configured parameters
        DSSDocument signatureWithER = xadesService.addEvidenceRecord(signatureDocument, evidenceRecordDocument, parameters);
        // end::add-er[]

        assertNotNull(signatureWithER);

    }

    @Test
    void erToContainerTest() {
        DSSDocument archiveDataObject = new FileDocument("src/test/resources/snippets/archive-data-object.xml");
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/snippets/evidence-record.ers");

        DSSDocument manifestDocument = null;

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

        // tag::er-to-asic[]
        // import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
        // import eu.europa.esig.dss.asic.common.ASiCContainerEvidenceRecordParameters;
        // import eu.europa.esig.dss.enumerations.ASiCContainerType;
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.spi.validation.CertificateVerifier;

        // Create a ASiCWithCAdESService to be used to add an existing evidence record to a container
        // NOTE: CertificateVerifier may provide an additional configuration for validation
        //       of evidence record and its timestamps
        ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier);

        // Configure the Evidence Record container incorporation parameters
        ASiCContainerEvidenceRecordParameters parameters = new ASiCContainerEvidenceRecordParameters();

        // Define a target container file.
        // When evidence record is being added within an existing container,
        // the value shall correspond to the container type.
        parameters.setContainerType(ASiCContainerType.ASiC_E);

        // (Optional) Provide a custom ASiCEvidenceRecordManifest document.
        // When not provided, a new ASiCEvidenceRecordManifest document will be created based
        // on the data objects covered by the evidence record.
        // NOTE: applicable only for ASiC-E containers.
        parameters.setAsicEvidenceRecordManifest(manifestDocument);

        // Create an ASiC container with the incorporated evidence record.
        DSSDocument containerWithER = service.addContainerEvidenceRecord(archiveDataObject, evidenceRecordDocument, parameters);
        // end::er-to-asic[]
    }

}
