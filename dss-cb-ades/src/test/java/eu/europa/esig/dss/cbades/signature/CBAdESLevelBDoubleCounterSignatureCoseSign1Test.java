package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.cbades.COSECounterSignStructure;
import eu.europa.esig.dss.cbades.COSECounterSignature;
import eu.europa.esig.dss.cbades.COSECounterSignatureParser;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBDoubleCounterSignatureCoseSign1Test extends AbstractCBAdESCounterSignatureTest {

    private CBAdESService service;
    private DSSDocument documentToSign;

    CBAdESSignatureParameters signatureParameters;
    CBAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "doc.txt");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        counterSignatureParameters = new CBAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        SignerLocation signerLocation = new SignerLocation();
        signerLocation.setLocality("Kehlen");
        counterSignatureParameters.bLevel().setSignerLocation(signerLocation);
        counterSignatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(CommitmentTypeEnum.ProofOfCreation));
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESCounterSignatureParameters getCounterSignatureParameters() {
        return counterSignatureParameters;
    }

    @Override
    protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
        DSSDocument counterSigned = super.counterSign(signatureDocument, signatureId);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, 1);
        counterSignatureParameters.bLevel().setSigningDate(calendar.getTime());

        return super.counterSign(counterSigned, signatureId);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        InMemoryDocument signedDocument = new InMemoryDocument(byteArray);
        assertTrue(COSEParser.isSupported(signedDocument));

        COSEParser coseParser = COSEParser.fromDocument(signedDocument);
        COSESignStructure coseSignStructure = coseParser.parse();
        assertNotNull(coseSignStructure);

        assertEquals(COSESignatureType.COSE_SIGN1, coseSignStructure.getContext());
        COSESign1 coseSign1 = assertInstanceOf(COSESign1.class, coseSignStructure);

        COSEUnprotectedHeader unprotectedHeader = coseSign1.getUnprotectedHeader();
        assertNotNull(unprotectedHeader);
        assertFalse(unprotectedHeader.isEmpty());
        assertEquals(1, unprotectedHeader.getSize());

        CBORArray uHeaders = unprotectedHeader.getAsArray(COSEHeaderParameter.U_HEADERS.cbor());
        assertNotNull(uHeaders);
        assertEquals(2, uHeaders.getSize());

        List<CBORObject> items = uHeaders.getValueAsList();
        assertEquals(2, items.size());

        for (CBORObject countersignature : items) {
            assertTrue(countersignature.isByteString());

            CBORObject countersignatureComponent = CBORUtils.parseCbor(countersignature.getValueAsBytes());
            assertTrue(countersignatureComponent.isMap());

            CBORMap countersignatureMap = (CBORMap) countersignatureComponent;
            assertEquals(1, countersignatureMap.getSize());

            CBORObject counterSignatureV2Object = countersignatureMap.getHeader(COSEHeaderParameter.COUNTER_SIGNATURE_V2.cbor());
            assertNotNull(counterSignatureV2Object);
            assertFalse(counterSignatureV2Object.isTagged());
            assertTrue(counterSignatureV2Object.isArray());

            COSECounterSignStructure coseCounterSignStructure = COSECounterSignatureParser.fromCBORObject(counterSignatureV2Object)
                    .setContext(COSESignatureType.COSE_COUNTER_SIGNATURE_V2)
                    .setMasterSignature(coseSign1)
                    .parse();
            assertNotNull(coseCounterSignStructure);
            assertEquals(COSESignatureType.COSE_COUNTER_SIGNATURE_V2, coseCounterSignStructure.getContext());

            COSECounterSignature coseCounterSignature = assertInstanceOf(COSECounterSignature.class, coseCounterSignStructure);
            assertNotNull(coseCounterSignature.getProtectedHeader());
            assertNotNull(coseCounterSignature.getUnprotectedHeader());
            assertNotNull(coseCounterSignature.getSignature());
            assertNotNull(coseCounterSignature.getMasterSignature());

            COSEProtectedHeader protectedHeader = coseCounterSignature.getProtectedHeader();

            CBORObject cty = protectedHeader.getHeader(COSEHeaderParameter.CONTENT_TYPE.cbor());
            assertNull(cty);
        }
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(3, Utils.collectionSize(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        super.checkSignatureScopes(diagnosticData);

        int counterSignatureCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                List<XmlSignatureScope> signatureScopes = signatureWrapper.getSignatureScopes();
                assertEquals(2, signatureScopes.size());

                XmlSignatureScope xmlSignatureScope = signatureScopes.get(0);
                assertEquals(SignatureScopeType.COUNTER_SIGNATURE, xmlSignatureScope.getScope());
                assertEquals(signatureWrapper.getParent().getId(), xmlSignatureScope.getName());

                xmlSignatureScope = signatureScopes.get(1);
                assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());

                ++counterSignatureCounter;
            }
        }
        assertEquals(2, counterSignatureCounter);
    }

    @Override
    protected void checkCommitmentTypeIndications(DiagnosticData diagnosticData) {
        super.checkCommitmentTypeIndications(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<XmlCommitmentTypeIndication> commitmentTypeIndications = signature.getCommitmentTypeIndications();
            if (signature.isCounterSignature()) {
                assertEquals(1, commitmentTypeIndications.size());
                XmlCommitmentTypeIndication commitmentTypeIndication = commitmentTypeIndications.get(0);
                assertEquals(CommitmentTypeEnum.ProofOfCreation.getUri(), commitmentTypeIndication.getIdentifier());
                assertEquals(CommitmentTypeEnum.ProofOfCreation.getDescription(), commitmentTypeIndication.getDescription());
                assertEquals(CommitmentTypeEnum.ProofOfCreation.getDocumentationReferences().length,
                        commitmentTypeIndication.getDocumentationReferences().size());
            } else {
                assertEquals(0, commitmentTypeIndications.size());
            }
        }
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CounterSignatureService<CBAdESCounterSignatureParameters> getCounterSignatureService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
