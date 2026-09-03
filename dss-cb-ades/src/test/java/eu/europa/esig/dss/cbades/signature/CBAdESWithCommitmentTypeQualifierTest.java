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

import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzer;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESWithCommitmentTypeQualifierTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private CBAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private Date currentTime;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getOfflineCertificateVerifier());
        documentToSign = new InMemoryDocument("Hello world!".getBytes(), "HelloWorld");

        currentTime = new Date();

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(currentTime);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        CommonCommitmentType commonCommitmentType = new CommonCommitmentType();
        commonCommitmentType.setOid(CommitmentTypeEnum.ProofOfApproval.getOid());

        CommitmentQualifier asn1CommitmentQualifier = new CommitmentQualifier();
        CBORArray cborArray = new CBORArray();
        cborArray.add("1.2.4.5.6");
        cborArray.add(CBORUtils.formatToTDate(currentTime));
        asn1CommitmentQualifier.setContent(new InMemoryDocument(CBORUtils.serializeCborObject(cborArray)));

        CommitmentQualifier stringCommitmentQualifier = new CommitmentQualifier();
        stringCommitmentQualifier.setContent(new InMemoryDocument(CommitmentTypeEnum.ProofOfApproval.getUri().getBytes()));

        commonCommitmentType.setCommitmentTypeQualifiers(asn1CommitmentQualifier, stringCommitmentQualifier);

        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(commonCommitmentType));
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        COSEDocumentAnalyzer analyzer = new COSEDocumentAnalyzer(new InMemoryDocument(byteArray));
        List<AdvancedSignature> signatures = analyzer.getSignatures();
        assertEquals(1, signatures.size());

        CBAdESSignature signature = (CBAdESSignature) signatures.get(0);
        COSEProtectedHeader protectedHeader = signature.getCoseSignature().getSignerProtectedHeader();
        CBORObject commitmentType = protectedHeader.getHeader(COSEHeaderParameter.SR_CMS.cbor());
        assertNotNull(commitmentType);
        assertTrue(commitmentType.isArray());

        CBORArray commTypes = (CBORArray) commitmentType;
        assertEquals(1, commTypes.getSize());

        CBORObject commType = commTypes.getItem(0);
        assertTrue(commType.isMap());

        CBORMap commitmentTypeMap = (CBORMap) commType;

        CBORObject identifier = commitmentTypeMap.getHeader(COSEHeaderParameter.SR_CM_COMM_ID.cbor());
        assertNotNull(identifier);
        assertTrue(identifier.isMap());
        assertEquals("urn:oid:" + CommitmentTypeEnum.ProofOfApproval.getOid(), ((CBORMap) identifier).getAsString(COSEHeaderParameter.OID_ID.cbor()));

        CBORObject qualifiers = commitmentTypeMap.getHeader(COSEHeaderParameter.SR_CM_COMM_QUALS.cbor());
        assertNotNull(qualifiers);
        assertTrue(qualifiers.isArray());

        CBORArray qualifiersList = (CBORArray) qualifiers;
        assertEquals(2, qualifiersList.getSize());

        boolean asn1QualifierFound = false;
        boolean stringQualifierFound = false;
        for (CBORObject qualifier : qualifiersList.getValueAsList()) {
            if (qualifier.isArray()) {
                CBORArray qualifierArray = (CBORArray) qualifier;
                assertEquals(2, qualifierArray.getSize());
                assertEquals("1.2.4.5.6", qualifierArray.getAsString(0));
                assertEquals(DSSUtils.formatDateToRFC(currentTime), qualifierArray.getAsString(1));
                asn1QualifierFound = true;

            } else if (qualifier.isByteString()) {
                assertEquals(CommitmentTypeEnum.ProofOfApproval.getUri(), new String(((CBORByteString) qualifier).getValueAsBytes()));
                stringQualifierFound = true;
            }
        }
        assertTrue(asn1QualifierFound);
        assertTrue(stringQualifierFound);
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
