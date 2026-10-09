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

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
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
        CBORValue cborValue = CBOR.array()
                .add("1.2.4.5.6")
                .add(CBORUtils.formatToTDate(currentTime))
                .value();
        asn1CommitmentQualifier.setContent(new InMemoryDocument(CBORUtils.serializeCbor(cborValue)));

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
        CBORValue commitmentType = protectedHeader.getHeader(COSEHeaderParameter.SR_CMS.cbor());
        assertNotNull(commitmentType);
        assertTrue(commitmentType.isArray());

        assertEquals(1, commitmentType.size());

        CBORValue commType = commitmentType.get(0);
        assertTrue(commType.isMap());

        CBORValue identifier = commType.get(COSEHeaderParameter.SR_CM_COMM_ID.cbor());
        assertNotNull(identifier);
        assertTrue(identifier.isMap());

        CBORValue oid = identifier.get(COSEHeaderParameter.OID_ID.cbor());
        assertNotNull(oid);
        assertTrue(oid.isTag());
        assertEquals(32, oid.getTag().longValue());
        assertNotNull(oid.getTaggedValue());
        assertTrue(oid.getTaggedValue().isTextString());

        assertEquals("urn:oid:" + CommitmentTypeEnum.ProofOfApproval.getOid(), oid.getTaggedValue().asString());

        CBORValue qualifiers = commType.get(COSEHeaderParameter.SR_CM_COMM_QUALS.cbor());
        assertNotNull(qualifiers);
        assertTrue(qualifiers.isArray());

        assertEquals(2, qualifiers.size());

        boolean asn1QualifierFound = false;
        boolean stringQualifierFound = false;
        for (CBORValue qualifier : qualifiers.getElements()) {
            if (qualifier.isArray()) {
                assertEquals(2, qualifier.size());
                assertEquals("1.2.4.5.6", qualifier.getAsStringOrNull(0));
                assertEquals(DSSUtils.formatDateToRFC(currentTime), qualifier.getAsStringOrNull(1));
                asn1QualifierFound = true;

            } else if (qualifier.isByteString()) {
                assertEquals(CommitmentTypeEnum.ProofOfApproval.getUri(), new String(qualifier.asBytes()));
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
