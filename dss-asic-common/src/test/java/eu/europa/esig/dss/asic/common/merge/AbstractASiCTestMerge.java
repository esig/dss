package eu.europa.esig.dss.asic.common.merge;

import eu.europa.esig.dss.asic.common.ASiCTestUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCTestMerge<SP extends SerializableSignatureParameters,
        TP extends SerializableTimestampParameters> extends AbstractPkiFactoryTestValidation<SP, TP> {

    private String signingAlias;

    @Test
    public void createTwoContainersAndMerge() throws Exception {
        signingAlias = getFirstSigningAlias();
        DSSDocument firstSignedContainer = getFirstSignedContainer();

        signingAlias = getSecondSigningAlias();
        DSSDocument secondSignedContainer = getSecondSignedContainer();

        ASiCContainerMerger asicContainerMerger = getASiCContainerMerger(firstSignedContainer, secondSignedContainer);
        DSSDocument mergeResult = asicContainerMerger.merge();

        // mergeResult.save("target/" + mergeResult.getName());

        ASiCTestUtils.verifyZipContainer(mergeResult);
        verify(mergeResult);
    }

    protected DSSDocument getFirstSignedContainer() {
        ToBeSigned dataToSign = getService().getDataToSign(getFirstSignedData(), getFirstSignatureParameters());
        SignatureValue signatureValue = getToken().sign(dataToSign, getFirstSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
        return getService().signDocument(getFirstSignedData(), getFirstSignatureParameters(), signatureValue);
    }

    protected abstract List<DSSDocument> getFirstSignedData();

    protected abstract String getFirstSigningAlias();

    protected abstract SP getFirstSignatureParameters();

    protected abstract SP getSecondSignatureParameters();

    protected DSSDocument getSecondSignedContainer() {
        ToBeSigned dataToSign = getService().getDataToSign(getSecondSignedData(), getSecondSignatureParameters());
        SignatureValue signatureValue = getToken().sign(dataToSign, getSecondSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
        return getService().signDocument(getSecondSignedData(), getSecondSignatureParameters(), signatureValue);
    }

    protected abstract List<DSSDocument> getSecondSignedData();

    protected abstract String getSecondSigningAlias();

    protected abstract MultipleDocumentsSignatureService<SP, TP> getService();

    protected ASiCContainerMerger getASiCContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        return DefaultContainerMerger.fromDocuments(containerOne, containerTwo);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        SignatureWrapper firstSignature = diagnosticData.getSignatures().get(0);
        for (DSSDocument document : getFirstSignedData()) {
            boolean documentFound = false;
            for (XmlSignatureScope signatureScope : firstSignature.getSignatureScopes()) {
                if (document.getName().equals(signatureScope.getName())) {
                    documentFound = true;
                }
            }
            assertTrue(documentFound);
        }

        SignatureWrapper secondSignature = diagnosticData.getSignatures().get(1);
        for (DSSDocument document : getSecondSignedData()) {
            boolean documentFound = false;
            for (XmlSignatureScope signatureScope : secondSignature.getSignatureScopes()) {
                if (document.getName().equals(signatureScope.getName())) {
                    documentFound = true;
                }
            }
            assertTrue(documentFound);
        }
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
