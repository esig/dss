package eu.europa.esig.dss.asic.xades.merge.asice;

import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.merge.ASiCEWithXAdESContainerMerger;
import eu.europa.esig.dss.asic.xades.merge.AbstractWithXAdESTestMerge;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESLevelBContainerMergerCustomSigNameTest extends AbstractWithXAdESTestMerge {

    private DSSDocument documentToSign;

    private ASiCWithXAdESService service;

    private ASiCWithXAdESSignatureParameters firstSignatureParameters;
    private ASiCWithXAdESSignatureParameters secondSignatureParameters;

    @BeforeEach
    public void init() {
        documentToSign = new FileDocument("src/test/resources/signable/test.txt");

        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signaturesAAA.xml");
        service.setAsicFilenameFactory(filenameFactory);

        Date signingTime = new Date();

        firstSignatureParameters = new ASiCWithXAdESSignatureParameters();
        firstSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        firstSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        firstSignatureParameters.bLevel().setSigningDate(signingTime);

        secondSignatureParameters = new ASiCWithXAdESSignatureParameters();
        secondSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        secondSignatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        secondSignatureParameters.bLevel().setSigningDate(signingTime);
    }

    @Override
    protected ASiCContainerMerger getASiCContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        ASiCContainerMerger asicContainerMerger = super.getASiCContainerMerger(containerOne, containerTwo);
        assertTrue(asicContainerMerger instanceof ASiCEWithXAdESContainerMerger);
        ASiCEWithXAdESContainerMerger xadesContainerMerger = (ASiCEWithXAdESContainerMerger) asicContainerMerger;

        SimpleASiCWithXAdESFilenameFactory filenameFactory = new SimpleASiCWithXAdESFilenameFactory();
        filenameFactory.setSignatureFilename("signaturesBBB.xml");
        xadesContainerMerger.setAsicFilenameFactory(filenameFactory);

        return xadesContainerMerger;
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        assertEquals(2, diagnosticData.getSignatures().size());

        boolean aaaSigFound = false;
        boolean bbbSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if ("META-INF/signaturesAAA.xml".equals(signatureWrapper.getSignatureFilename())) {
                aaaSigFound = true;
            } else if ("META-INF/signaturesBBB.xml".equals(signatureWrapper.getSignatureFilename())) {
                bbbSigFound = true;
            }
        }
        assertTrue(aaaSigFound);
        assertTrue(bbbSigFound);
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
    protected ASiCWithXAdESSignatureParameters getFirstSignatureParameters() {
        firstSignatureParameters.setSigningCertificate(getSigningCert());
        firstSignatureParameters.setCertificateChain(getCertificateChain());
        return firstSignatureParameters;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSecondSignatureParameters() {
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
    protected MultipleDocumentsSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

}
