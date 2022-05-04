package eu.europa.esig.dss.asic.cades.merge.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.merge.AbstractWithCAdESTestMerge;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

public class ASiCEWithCAdESLevelBContainerMergerSameSigParamsTest extends AbstractWithCAdESTestMerge {

    private DSSDocument documentToSign;

    private ASiCWithCAdESService service;

    private ASiCWithCAdESSignatureParameters firstSignatureParameters;
    private ASiCWithCAdESSignatureParameters secondSignatureParameters;

    @BeforeEach
    public void init() {
        documentToSign = new FileDocument("src/test/resources/signable/test.txt");

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());

        Date signingTime = new Date();

        firstSignatureParameters = new ASiCWithCAdESSignatureParameters();
        firstSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        firstSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        firstSignatureParameters.bLevel().setSigningDate(signingTime);

        secondSignatureParameters = new ASiCWithCAdESSignatureParameters();
        secondSignatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        secondSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        secondSignatureParameters.bLevel().setSigningDate(signingTime);
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
        return Collections.singletonList(documentToSign);
    }

    @Override
    protected List<DSSDocument> getSecondSignedData() {
        return Collections.singletonList(documentToSign);
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
        return GOOD_USER;
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