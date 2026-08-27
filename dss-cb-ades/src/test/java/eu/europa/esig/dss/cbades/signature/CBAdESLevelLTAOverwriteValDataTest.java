/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cbades.signature;

import co.nstant.in.cbor.model.DataItem;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.AbstractCBAdESTestValidation;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.ListIterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelLTAOverwriteValDataTest extends AbstractCBAdESTestValidation {

    @Test
    void test() throws Exception {
        DSSDocument documentToSign = new InMemoryDocument("Hello world!".getBytes(), "HelloWorld");

        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LT);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);

        CBAdESService service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        service.setTspSource(getGoodTsa());
        CBAdESSignatureParameters extendParameters = new CBAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_LTA);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(null);
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        service = new CBAdESService(certificateVerifier);
        service.setTspSource(getGoodTsaCrossCertification());
        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);

        DSSDocument sigWithRemovedArcTst = removeLastArcTst(doubleLTADoc);

        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsaCrossCertification());

        DSSDocument doubleLTADocWithUpdatedTstVD = service.extendDocument(sigWithRemovedArcTst, extendParameters);
        checkSignedDocument(doubleLTADocWithUpdatedTstVD);

        Reports reports = verify(doubleLTADocWithUpdatedTstVD);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(3, timestampIds.size());

    }

    private DSSDocument removeLastArcTst(DSSDocument document) {
        assertTrue(CBORUtils.isCbor(document));

        byte[] binaries = DSSUtils.toByteArray(document);
        CBORObject cborObject = CBORUtils.parseCbor(binaries);
        assertNotNull(cborObject);
        assertTrue(cborObject.isArray());

        CBORArray coseSign1 = (CBORArray) cborObject;
        assertEquals(4, coseSign1.getSize());

        ListIterator<DataItem> it = getUHeadersIterator(coseSign1);
        DataItem uHeaderDataItem = it.previous();
        CBORObject uHeaderComponent = CBORObjectFactory.toCBORObject(uHeaderDataItem);
        assertTrue(uHeaderComponent.isByteString());
        CBORByteString cborByteString = (CBORByteString) uHeaderComponent;
        assertTrue(Utils.isArrayNotEmpty(cborByteString.getValueAsBytes()));

        CBORObject parsedUHeaderItem = CBORUtils.parseCbor(cborByteString.getValueAsBytes());
        assertNotNull(parsedUHeaderItem);
        assertTrue(parsedUHeaderItem.isMap());

        CBORMap uHeaderItemMap = (CBORMap) parsedUHeaderItem;
        assertTrue(uHeaderItemMap.containsKey(COSEHeaderParameter.ARC_TST.cbor()));
        it.remove();

        byte[] sigWithRemovedLastArcTst = CBORUtils.serializeCborObject(cborObject);
        cborObject = CBORUtils.parseCbor(sigWithRemovedLastArcTst);
        assertNotNull(cborObject);
        assertTrue(cborObject.isArray());

        coseSign1 = (CBORArray) cborObject;

        it = getUHeadersIterator(coseSign1);
        uHeaderDataItem = it.previous();
        uHeaderComponent = CBORObjectFactory.toCBORObject(uHeaderDataItem);
        assertTrue(uHeaderComponent.isByteString());
        cborByteString = (CBORByteString) uHeaderComponent;
        assertTrue(Utils.isArrayNotEmpty(cborByteString.getValueAsBytes()));

        parsedUHeaderItem = CBORUtils.parseCbor(cborByteString.getValueAsBytes());
        assertNotNull(parsedUHeaderItem);
        assertTrue(parsedUHeaderItem.isMap());
        uHeaderItemMap = (CBORMap) parsedUHeaderItem;
        assertTrue(uHeaderItemMap.containsKey(COSEHeaderParameter.VAL_DATA.cbor()));

        CBORMap valData = uHeaderItemMap.getAsMap(COSEHeaderParameter.VAL_DATA.cbor());
        assertNotNull(valData);
        assertNotNull(valData.getHeader(COSEHeaderParameter.VAL_DATA_X_VALS.cbor()));
        assertNull(valData.getHeader(COSEHeaderParameter.VAL_DATA_R_VALS.cbor()));

        return new InMemoryDocument(sigWithRemovedLastArcTst);
    }

    private ListIterator<DataItem> getUHeadersIterator(CBORArray coseSign1) {
        CBORObject unprotectedHeader = coseSign1.getItem(1);
        assertTrue(unprotectedHeader.isMap());

        CBORMap unprotectedHeaderMap = (CBORMap) unprotectedHeader;
        assertFalse(unprotectedHeaderMap.isEmpty());
        assertEquals(1, unprotectedHeaderMap.getSize());

        CBORObject uHeaders = unprotectedHeaderMap.getHeader(COSEHeaderParameter.U_HEADERS.cbor());
        assertNotNull(uHeaders);
        assertTrue(uHeaders.isArray());

        CBORArray uHeadersArray = (CBORArray) uHeaders;
        assertFalse(uHeadersArray.isEmpty());

        return uHeadersArray.toDataItem().getDataItems().listIterator(uHeadersArray.getSize());
    }

    private void checkSignedDocument(DSSDocument document) {
        assertTrue(CBORUtils.isCbor(document));

        byte[] binaries = DSSUtils.toByteArray(document);
        CBORObject cborObject = CBORUtils.parseCbor(binaries);
        assertNotNull(cborObject);
        assertTrue(cborObject.isArray());

        CBORArray coseSign1 = (CBORArray) cborObject;
        assertEquals(4, coseSign1.getSize());

        ListIterator<DataItem> it = getUHeadersIterator(coseSign1);

        int arcTstCounter = 0;
        int valDataCounter = 0;

        while (it.hasPrevious()) {
            DataItem uHeaderDataItem = it.previous();
            CBORObject uHeaderItem = CBORObjectFactory.toCBORObject(uHeaderDataItem);
            assertTrue(uHeaderItem.isByteString());
            CBORByteString cborByteString = (CBORByteString) uHeaderItem;
            assertTrue(Utils.isArrayNotEmpty(cborByteString.getValueAsBytes()));

            CBORObject parsedUHeaderItem = CBORUtils.parseCbor(cborByteString.getValueAsBytes());
            assertNotNull(parsedUHeaderItem);
            assertTrue(parsedUHeaderItem.isMap());

            CBORMap cborMap = (CBORMap) parsedUHeaderItem;
            if (cborMap.containsKey(COSEHeaderParameter.ARC_TST.cbor())) {
                ++arcTstCounter;

            } else if (cborMap.containsKey(COSEHeaderParameter.VAL_DATA.cbor())) {
                CBORMap valData = cborMap.getAsMap(COSEHeaderParameter.VAL_DATA.cbor());
                assertNotNull(valData);

                CBORArray xVals = valData.getAsArray(COSEHeaderParameter.VAL_DATA_X_VALS.cbor());
                assertNotNull(xVals);
                assertFalse(xVals.isEmpty());

                CBORMap rVals = valData.getAsMap(COSEHeaderParameter.VAL_DATA_R_VALS.cbor());
                assertNotNull(rVals);
                assertFalse(rVals.isEmpty());

                ++valDataCounter;
            }
        }

        assertEquals(2, arcTstCounter);
        assertEquals(2, valDataCounter);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_TIMESTAMPS_ONLY);
        return validator;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(3, diagnosticData.getTimestampList().size());

        int sigTstCounter = 0;
        int arcTstCounter = 0;
        int coveredCerts = 0;
        int coveredRevocation = 0;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++sigTstCounter;

            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++arcTstCounter;
                assertTrue(timestampWrapper.getTimestampedCertificates().size() > coveredCerts);
                assertTrue(timestampWrapper.getTimestampedRevocations().size() > coveredRevocation);
                coveredCerts = timestampWrapper.getTimestampedCertificates().size();
                coveredRevocation = timestampWrapper.getTimestampedRevocations().size();
            }
        }
        assertEquals(1, sigTstCounter);
        assertEquals(2, arcTstCounter);
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    public void validate() {
        // do nothing
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

}
