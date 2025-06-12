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
package eu.europa.esig.dss.cades.evidencerecord;

import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CAdESUnsignedAttributes;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.SignatureValidationAlerter;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.spi.OID.id_aa_er_external;
import static eu.europa.esig.dss.spi.OID.id_aa_er_internal;

/**
 * This class is used to embed an existing ERS evidence record within a CAdES signature as an unsigned property
 *
 */
public class CAdESEmbeddedEvidenceRecordBuilder {

    /**
     * The CertificateVerifier to be used for timestamps validation
     */
    private final CertificateVerifier certificateVerifier;

    /** A signature signed manifest. Used for ASiC */
    private ManifestFile manifestFile;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier} providing configuration for evidence record validation
     */
    public CAdESEmbeddedEvidenceRecordBuilder(final CertificateVerifier certificateVerifier) {
        this.certificateVerifier = new CertificateVerifierBuilder(certificateVerifier).buildOfflineCopy();
    }

    /**
     * Sets a signed manifest file
     * NOTE: ASiC only
     *
     * @param manifestFile {@link ManifestFile}
     */
    public void setManifestFile(ManifestFile manifestFile) {
        this.manifestFile = manifestFile;
    }

    /**
     * Adds the evidence record document to a signature with the given {@code signatureId},
     * provided the evidence record correctly applies to the signature
     *
     * @param signatureDocument {@link DSSDocument} where the evidence record will be added
     * @param evidenceRecordDocument {@link DSSDocument} to add
     * @param parameters {@link CAdESEvidenceRecordIncorporationParameters} to be used for the process configuration
     * @return {@link DSSDocument} with a signature containing the evidence record as an unsigned property
     */
    public DSSDocument addEvidenceRecord(DSSDocument signatureDocument, DSSDocument evidenceRecordDocument,
                                         CAdESEvidenceRecordIncorporationParameters parameters) {
        Objects.requireNonNull(signatureDocument, "Signature document must be provided!");
        Objects.requireNonNull(evidenceRecordDocument, "Evidence record document must be provided!");
        Objects.requireNonNull(parameters, "CAdESEvidenceRecordIncorporationParameters must be provided!");

        final CMSDocumentAnalyzer documentAnalyzer = initDocumentAnalyzer(signatureDocument, parameters.getDetachedContents());

        CAdESSignature signature = getCAdESSignature(documentAnalyzer, parameters.getSignatureId());
        assertSignatureExtensionPossible(signature, parameters);

        CAdESAttribute unsignedAttribute = getUnsignedAttributeToEmbed(signature, parameters);
        EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordDocument, signature, unsignedAttribute, parameters.getDetachedContents());
        assertEvidenceRecordValid(evidenceRecord, parameters);

        final List<SignerInformation> newSignerInformationList = new ArrayList<>();
        for (AdvancedSignature currentSignature : documentAnalyzer.getSignatures()) {
            CAdESSignature cadesSignature = (CAdESSignature) currentSignature;
            if (signature.equals(cadesSignature)) {
                SignerInformation newSignerInformation = addEvidenceRecordUnsignedProperty(cadesSignature, evidenceRecord, unsignedAttribute);
                newSignerInformationList.add(newSignerInformation);
            } else {
                newSignerInformationList.add(cadesSignature.getSignerInformation());
            }
        }
        final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
        CMS cms = CMSUtils.replaceSigners(signature.getCMS(), newSignerStore);
        return new InMemoryDocument(cms.getEncoded()); // preserve original coding
    }

    /**
     * Gets a signature to incorporate evidence record into
     *
     * @param documentAnalyzer {@link DefaultDocumentAnalyzer}
     * @param signatureId {@link String} identifier of a signature to return
     * @return {@link CAdESSignature}
     */
    protected CAdESSignature getCAdESSignature(DefaultDocumentAnalyzer documentAnalyzer, String signatureId) {
        if (signatureId != null) {
            AdvancedSignature signature = documentAnalyzer.getSignatureById(signatureId);
            if (signature == null) {
                throw new IllegalArgumentException(String.format("Unable to find a signature with Id : %s!", signatureId));
            }
            return (CAdESSignature) signature;

        } else {
            List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();
            if (Utils.isCollectionEmpty(signatures)) {
                throw new IllegalInputException(String.format("No signatures found in the document with name '%s'",
                        documentAnalyzer.getDocument().getName()));
            } else if (Utils.collectionSize(signatures) > 1) {
                throw new IllegalArgumentException(String.format("More than one signature found in a document with name '%s'! " +
                        "Please provide a signatureId within the parameters.", documentAnalyzer.getDocument().getName()));
            }
            // if one signature
            return (CAdESSignature) signatures.get(0);
        }
    }

    private CAdESAttribute getUnsignedAttributeToEmbed(CAdESSignature signature, CAdESEvidenceRecordIncorporationParameters parameters) {
        if (parameters.isParallelEvidenceRecord()) {
            CAdESUnsignedAttributes unsignedAttributes = CAdESUnsignedAttributes.build(signature.getSignerInformation());
            if (unsignedAttributes.isExist()) {
                List<CAdESAttribute> attributes = unsignedAttributes.getAttributes();
                CAdESAttribute lastUnsignedAttribute = attributes.get(attributes.size() - 1);
                if (lastUnsignedAttribute.isEvidenceRecord()) {
                    ASN1ObjectIdentifier expectedEvidenceRecordAttributeType = getEvidenceRecordUnsignedPropertyOID(signature);
                    if (!expectedEvidenceRecordAttributeType.equals(lastUnsignedAttribute.getASN1Oid())) {
                        throw new IllegalInputException(String.format(
                                "Unable to embed the parallel evidence record. Expected type '%s', obtained type '%s'.",
                                lastUnsignedAttribute.getASN1Oid().getId(), expectedEvidenceRecordAttributeType.getId()));
                    }
                    return lastUnsignedAttribute;
                }
            }

        }
        // new CAdESAttribute to be created
        return null;
    }

    private EvidenceRecord getEvidenceRecord(DSSDocument evidenceRecordDocument, CAdESSignature signature,
                                             CAdESAttribute unsignedAttribute, List<DSSDocument> detachedContents) {
        try {
            EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);

            final CAdESEmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper = new CAdESEmbeddedEvidenceRecordHelper(signature, unsignedAttribute);
            if (Utils.isCollectionNotEmpty(detachedContents)) {
                evidenceRecordAnalyzer.setEvidenceRecordIncorporationType(EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD);
                embeddedEvidenceRecordHelper.setDetachedContents(detachedContents);
            }
            evidenceRecordAnalyzer.setEmbeddedEvidenceRecordHelper(embeddedEvidenceRecordHelper);

            return evidenceRecordAnalyzer.getEvidenceRecord();

        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "Unable to build an evidence record from the provided document. Reason : %s", e.getMessage()), e);
        }
    }

    private void validateTimestamps(EvidenceRecord evidenceRecord) {
        SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(certificateVerifier);

        validationContext.addDocumentCertificateSource(evidenceRecord.getCertificateSource());
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            validationContext.addTimestampTokenForVerification(timestampToken);
        }

        validationContext.validate();

        SignatureValidationAlerter signatureValidationAlerter = new SignatureValidationAlerter(validationContext);
        signatureValidationAlerter.setSigningOperation(SigningOperation.ADD_EVIDENCE_RECORD);
        signatureValidationAlerter.assertAllTimestampsValid();
    }

    private CMSDocumentAnalyzer initDocumentAnalyzer(DSSDocument signatureDocument, List<DSSDocument> detachedContents) {
        CMSDocumentAnalyzer analyzer = new CMSDocumentAnalyzer(signatureDocument);
        analyzer.setManifestFile(manifestFile);
        analyzer.setDetachedContents(detachedContents);
        return analyzer;
    }

    private SignerInformation addEvidenceRecordUnsignedProperty(CAdESSignature signature, EvidenceRecord evidenceRecord,
                                                                CAdESAttribute unsignedAttribute) {
        ASN1ObjectIdentifier attributeOID = getEvidenceRecordUnsignedPropertyOID(signature);
        Attribute evidenceRecordAttribute = getEvidenceRecordAttribute(evidenceRecord, attributeOID, unsignedAttribute);

        SignerInformation signerInformation = signature.getSignerInformation();
        AttributeTable unsignedAttributesWithER = getUnsignedPropertiesTable(signerInformation, evidenceRecordAttribute, unsignedAttribute != null);
        return CMSUtils.replaceUnsignedAttributes(signerInformation, unsignedAttributesWithER);
    }

    private Attribute getEvidenceRecordAttribute(EvidenceRecord evidenceRecord, ASN1ObjectIdentifier attributeOID,
                                                 CAdESAttribute unsignedAttribute) {
        ASN1Sequence asn1EvidenceRecord = getASN1EvidenceRecord(evidenceRecord);
        if (unsignedAttribute != null) {
            // existing unsigned property
            final ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
            asn1EncodableVector.addAll(unsignedAttribute.getAttrValues().toArray());
            asn1EncodableVector.add(asn1EvidenceRecord);
            return new Attribute(attributeOID, new DERSet(asn1EncodableVector));

        } else {
            // new unsigned property
            return new Attribute(attributeOID, new DERSet(asn1EvidenceRecord));
        }
    }

    private AttributeTable getUnsignedPropertiesTable(SignerInformation signerInformation, Attribute evidenceRecordAttribute,
                                                      boolean parallelER) {
        AttributeTable unsignedAttributes = CAdESUtils.getUnsignedAttributes(signerInformation);
        int originalAttributeTableLength = unsignedAttributes.size();
        if (parallelER) {
            --originalAttributeTableLength;
        }

        final ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        for (int i = 0; i < originalAttributeTableLength; i++) {
            ASN1Encodable attribute = unsignedAttributes.toASN1EncodableVector().get(i);
            asn1EncodableVector.add(attribute);
        }
        asn1EncodableVector.add(evidenceRecordAttribute);
        return new AttributeTable(asn1EncodableVector);
    }

    private ASN1Sequence getASN1EvidenceRecord(EvidenceRecord evidenceRecord) {
        return ASN1Sequence.getInstance(evidenceRecord.getEncoded());
    }

    private ASN1ObjectIdentifier getEvidenceRecordUnsignedPropertyOID(CAdESSignature signature) {
        if (signature.getCMS().isDetachedSignature()) {
            return id_aa_er_external;
        } else {
            return id_aa_er_internal;
        }
    }

    private void assertEvidenceRecordValid(EvidenceRecord evidenceRecord, CAdESEvidenceRecordIncorporationParameters parameters) {
        if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD != evidenceRecord.getEvidenceRecordType()) {
            throw new IllegalInputException(String.format("Only RFC 4998 ERS type of Evidence Records is allowed " +
                    "for CAdES signatures! Identified type of evidence record: '%s'", evidenceRecord.getEvidenceRecordType()));
        }
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            if (!referenceValidation.isIntact()) {
                switch (referenceValidation.getType()) {
                    case EVIDENCE_RECORD_MASTER_SIGNATURE:
                        throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                                "the digest computed on the signature!");
                    case EVIDENCE_RECORD_ARCHIVE_OBJECT:
                        if (Utils.isCollectionEmpty(parameters.getDetachedContents())) {
                            throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                                    "the digest computed on the detached content! " +
                                    "Please use #setDetachedContent method to provide original documents.");
                        } else {
                            throw new IllegalInputException("The digest covered by the evidence record do not correspond to " +
                                    "the digest computed on the detached content!");
                        }
                    case EVIDENCE_RECORD_ORPHAN_REFERENCE:
                        // acceptable status
                        break;
                    default:
                        throw new IllegalStateException(String.format(
                                "Unexpected digest matcher type '%s' does not correspond to the value present in " +
                                        "the evidence record!", referenceValidation.getType()));

                }
            }
        }
        validateTimestamps(evidenceRecord);
    }

    private void assertSignatureExtensionPossible(CAdESSignature signature, CAdESEvidenceRecordIncorporationParameters parameters) {
        CMSUtils.assertEvidenceRecordEmbeddingSupported();
        assertNoEvidenceRecordsInOtherSignerInfos(signature);

        if (CAdESUtils.containsATSTv2(signature.getSignerInformation())) {
            throw new IllegalInputException("Cannot add evidence record to a CAdES containing an archiveTimestampV2");
        }
        if (signature.getCMS().isDetachedSignature() && Utils.collectionSize(parameters.getDetachedContents()) != 1) {
            throw new IllegalArgumentException("One and only one detached document is allowed for an embedded evidence record in CAdES!");
        }
    }

    private void assertNoEvidenceRecordsInOtherSignerInfos(CAdESSignature signature) {
        for (SignerInformation signerInfo : signature.getCMS().getSignerInfos()) {
            if (signature.getSignerInformation() != signerInfo && CAdESUtils.containsEvidenceRecord(signerInfo)) {
                throw new IllegalInputException("At most one of the SignerInfo instances within " +
                        "the SignedData instance shall contain evidence-records attributes! " +
                        "Please abolish the operation or provide another signature Id.");
            }
        }
    }

}
