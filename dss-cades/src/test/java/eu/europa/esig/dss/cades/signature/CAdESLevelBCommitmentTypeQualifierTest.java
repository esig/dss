/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommitmentQualifier;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.CommitmentTypeQualifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.junit.jupiter.api.BeforeEach;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_commitmentType;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelBCommitmentTypeQualifierTest extends AbstractCAdESTestSignature {

    private static final String HELLO_WORLD = "Hello World";

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        CommonCommitmentType commonCommitmentType = new CommonCommitmentType();
        commonCommitmentType.setOid(CommitmentTypeEnum.ProofOfApproval.getOid());

        CommitmentQualifier asn1CommitmentQualifier = new CommitmentQualifier();
        asn1CommitmentQualifier.setOid("1.2.4.5.6");
        asn1CommitmentQualifier.setContent(new InMemoryDocument(DSSASN1Utils.getDEREncoded(new DERUTCTime(new Date()))));

        CommitmentQualifier stringCommitmentQualifier = new CommitmentQualifier();
        stringCommitmentQualifier.setOid("1.5.6.7.88");
        stringCommitmentQualifier.setContent(new InMemoryDocument(CommitmentTypeEnum.ProofOfApproval.getUri().getBytes()));

        commonCommitmentType.setCommitmentTypeQualifiers(asn1CommitmentQualifier, stringCommitmentQualifier);

        signatureParameters.bLevel().setCommitmentTypeIndications(Collections.singletonList(commonCommitmentType));

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        CMSDocumentValidator cmsDocumentValidator = new CMSDocumentValidator(new InMemoryDocument(byteArray));
        List<AdvancedSignature> signatures = cmsDocumentValidator.getSignatures();
        assertEquals(1, signatures.size());
        assertTrue(signatures.get(0) instanceof CAdESSignature);

        CAdESSignature signature = (CAdESSignature) signatures.get(0);
        CMSSignedData cmsSignedData = signature.getCmsSignedData();
        assertNotNull(cmsSignedData);

        SignerInformationStore signerInfos = cmsSignedData.getSignerInfos();
        assertEquals(1, signerInfos.size());

        SignerInformation signerInformation = signerInfos.getSigners().iterator().next();
        AttributeTable signedAttributes = signerInformation.getSignedAttributes();
        
        Attribute commitmentTypeAttribute = signedAttributes.get(id_aa_ets_commitmentType);
        assertNotNull(commitmentTypeAttribute);

        ASN1Encodable[] attributeValues = commitmentTypeAttribute.getAttributeValues();
        assertEquals(1, attributeValues.length);

        ASN1Encodable attributeValue = attributeValues[0];
        CommitmentTypeIndication commitmentTypeIndication = CommitmentTypeIndication.getInstance(attributeValue);
        assertEquals(CommitmentTypeEnum.ProofOfApproval.getOid(), commitmentTypeIndication.getCommitmentTypeId().getId());

        ASN1Sequence commitmentTypeQualifiers = commitmentTypeIndication.getCommitmentTypeQualifier();
        assertEquals(2, commitmentTypeQualifiers.size());

        boolean asn1EncodedQualifierFound = false;
        boolean stringQualifierFound = false;
        for (ASN1Encodable asn1Encodable : commitmentTypeQualifiers) {
            CommitmentTypeQualifier commitmentTypeQualifier = CommitmentTypeQualifier.getInstance(asn1Encodable);
            ASN1ObjectIdentifier commitmentTypeIdentifier = commitmentTypeQualifier.getCommitmentTypeIdentifier();
            assertNotNull(commitmentTypeIdentifier);

            String oid = commitmentTypeIdentifier.getId();
            if ("1.2.4.5.6".equals(oid)) {
                ASN1Encodable qualifier = commitmentTypeQualifier.getQualifier();
                assertNotNull(qualifier);
                assertNotNull(DERUTCTime.getInstance(qualifier));
                asn1EncodedQualifierFound = true;
            } else if ("1.5.6.7.88".equals(oid)) {
                ASN1Encodable qualifier = commitmentTypeQualifier.getQualifier();
                assertNotNull(qualifier);
                assertNotNull(ASN1UTF8String.getInstance(qualifier));
                stringQualifierFound = true;
            }
        }
        assertTrue(asn1EncodedQualifierFound);
        assertTrue(stringQualifierFound);
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected List<DSSDocument> getOriginalDocuments() {
        return Collections.singletonList(getDocumentToSign());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
