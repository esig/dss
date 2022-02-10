package eu.europa.esig.dss.asic.cades.extension.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.signature.AbstractASiCWithCAdESMultipleDocumentsTestSignature;
import eu.europa.esig.dss.asic.common.DSSZipEntry;
import eu.europa.esig.dss.asic.common.DSSZipEntryDocument;
import eu.europa.esig.dss.asic.common.SecureContainerHandler;
import eu.europa.esig.dss.asic.common.ContainerEntryDocument;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ASiCeExtensionWithCAdESBToLTAWithZipEntryDocTest extends AbstractASiCWithCAdESMultipleDocumentsTestSignature {

    private ContainerEntryDocument documentOne;
    private ContainerEntryDocument documentTwo;

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns = new ArrayList<>();

    @BeforeEach
    public void init() throws Exception {
        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        DSSZipEntry zipEntryOne = new DSSZipEntry("docOne.txt");
        zipEntryOne.setComment("Nowina Solutions document");

        documentOne = new ContainerEntryDocument(
                new InMemoryDocument("Hello World !".getBytes(), zipEntryOne.getName()), zipEntryOne);

        documentToSigns.add(documentOne);

        DSSZipEntry zipEntryTwo = new DSSZipEntry("docTwo.txt");
        zipEntryTwo.setCompressionMethod(ZipEntry.STORED);
        zipEntryTwo.setCreationTime(DSSUtils.getUtcDate(2020, 0, 1));

        documentTwo = new ContainerEntryDocument(
                new InMemoryDocument("Bye World !".getBytes(), zipEntryTwo.getName()), zipEntryTwo);

        documentToSigns.add(documentTwo);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
        secureContainerHandler.setExtractComments(true);
        ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);
    }

    @AfterAll
    public static void reset() {
        ZipUtils.getInstance().setZipContainerHandler(new SecureContainerHandler());
    }

    @Override
    protected DSSDocument sign() {
        try {
            DSSDocument signedDocument = super.sign();

            File file = new File("target/" + signedDocument.getName());
            signedDocument.save(file.getPath());
            assertTrue(file.exists());

            DSSDocument tempDocument = new FileDocument(file);
            verifyMetadata(tempDocument);

            signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
            DSSDocument extendedDocument = service.extendDocument(tempDocument, signatureParameters);

            extendedDocument.save(file.getPath());

            tempDocument = new FileDocument(file);
            verifyMetadata(tempDocument);

            assertTrue(file.delete());
            assertFalse(file.exists());

            return extendedDocument;

        } catch (IOException e) {
            fail(e);
            return null;
        }
    }

    private void verifyMetadata(DSSDocument archive) {
        List<DSSDocument> dssDocuments = ZipUtils.getInstance().extractContainerContent(archive);

        boolean firstDocFound = false;
        boolean secondDocFound = false;

        for (DSSDocument document : dssDocuments) {
            assertTrue(document instanceof DSSZipEntryDocument);
            DSSZipEntryDocument dssZipEntry = (DSSZipEntryDocument) document;
            DSSZipEntry entry = dssZipEntry.getZipEntry();

            if (documentOne.getName().equals(entry.getName())) {
                assertEquals(documentOne.getZipEntry().getComment(), entry.getComment());
                assertEquals(documentOne.getZipEntry().getCompressionMethod(), entry.getCompressionMethod());
                assertNull(entry.getCreationTime());
                firstDocFound = true;

            } else if (documentTwo.getName().equals(entry.getName())) {
                assertNull(entry.getComment());
                assertEquals(documentTwo.getZipEntry().getCompressionMethod(), entry.getCompressionMethod());
                assertEquals(documentTwo.getZipEntry().getCreationTime(), entry.getCreationTime());
                secondDocFound = true;
            }
        }
        assertTrue(firstDocFound);
        assertTrue(secondDocFound);
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeType.ASICE;
    }

    @Override
    protected boolean isBaselineT() {
        return false;
    }

    @Override
    protected boolean isBaselineLTA() {
        return false;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
