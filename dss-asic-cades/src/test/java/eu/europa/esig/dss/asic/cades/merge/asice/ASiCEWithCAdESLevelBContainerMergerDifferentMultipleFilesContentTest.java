package eu.europa.esig.dss.asic.cades.merge.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.merge.AbstractWithCAdESTestMerge;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ASiCEWithCAdESLevelBContainerMergerDifferentMultipleFilesContentTest extends AbstractWithCAdESTestMerge {

    private List<DSSDocument> documentsToSignOne;
    private List<DSSDocument> documentsToSignTwo;

    private ASiCWithCAdESService service;

    private ASiCWithCAdESSignatureParameters firstSignatureParameters;
    private ASiCWithCAdESSignatureParameters secondSignatureParameters;

    @BeforeEach
    public void init() {
        documentsToSignOne = Arrays.asList(new FileDocument("src/test/resources/signable/test.txt"),
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT));

        documentsToSignTwo = Arrays.asList(new FileDocument("src/test/resources/signable/test.txt"),
                new InMemoryDocument("Bye World!".getBytes(), "hello.txt", MimeType.TEXT));

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());

        firstSignatureParameters = new ASiCWithCAdESSignatureParameters();
        firstSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        firstSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        firstSignatureParameters.bLevel().setSigningDate(new Date());

        secondSignatureParameters = new ASiCWithCAdESSignatureParameters();
        secondSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        secondSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        secondSignatureParameters.bLevel().setSigningDate(new Date());
    }

    @Test
    @Override
    public void createTwoContainersAndMerge() throws Exception {
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> super.createTwoContainersAndMerge());
        assertEquals("Unable to merge containers. " +
                "Containers contain different documents under the same name : hello.txt!", exception.getMessage());
    }

    @Override
    protected DSSDocument getFirstSignedContainer() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signature001.p7s");
        getService().setAsicFilenameFactory(filenameFactory);
        return super.getFirstSignedContainer();
    }

    @Override
    protected DSSDocument getSecondSignedContainer() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signature002.p7s");
        getService().setAsicFilenameFactory(filenameFactory);
        return super.getSecondSignedContainer();
    }

    @Override
    protected List<DSSDocument> getFirstSignedData() {
        return documentsToSignOne;
    }

    @Override
    protected List<DSSDocument> getSecondSignedData() {
        return documentsToSignTwo;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getFirstSignatureParameters() {
        firstSignatureParameters.setSigningCertificate(getSigningCert());
        firstSignatureParameters.setCertificateChain(getCertificateChain());
        return firstSignatureParameters;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSecondSignatureParameters() {
        secondSignatureParameters.setSigningCertificate(getSigningCert());
        secondSignatureParameters.setCertificateChain(getCertificateChain());
        return secondSignatureParameters;
    }

    @Override
    protected String getFirstSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected String getSecondSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected ASiCContainerType getExpectedASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

}