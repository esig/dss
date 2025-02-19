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
package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.evidencerecord.AbstractSignatureEvidenceRecordDigestBuilder;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Computes message-imprint of a CMS signature to be protected by an evidence-record
 *
 */
public class CAdESEvidenceRecordDigestBuilder extends AbstractSignatureEvidenceRecordDigestBuilder {

    /**
     * Original document in case of a detached signature
     */
    protected DSSDocument detachedDocument;

    /**
     * Default constructor to instantiate CAdESEvidenceRecordDigestBuilder with a SHA-256 digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     */
    public CAdESEvidenceRecordDigestBuilder(final DSSDocument signatureDocument) {
       super(signatureDocument);
    }

    /**
     * Constructor to instantiate CAdESEvidenceRecordDigestBuilder with a custom digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     */
    public CAdESEvidenceRecordDigestBuilder(final DSSDocument signatureDocument, final DigestAlgorithm digestAlgorithm) {
        super(signatureDocument, digestAlgorithm);
    }

    /**
     * Sets an original document in case of a detached signature.
     * When set, please use {@code #buildExternalEvidenceRecordDigest} to compute hash for both the signature and the original document
     *
     * @param detachedDocument {@link DSSDocument} original document covered by the signature
     * @return this builder
     */
    public CAdESEvidenceRecordDigestBuilder setDetachedContent(DSSDocument detachedDocument) {
        this.detachedDocument = detachedDocument;
        return this;
    }

    @Override
    public CAdESEvidenceRecordDigestBuilder setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        return (CAdESEvidenceRecordDigestBuilder) super.setParallelEvidenceRecord(parallelEvidenceRecord);
    }

    @Override
    public Digest build() {
        final CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signatureDocument);
        return getDigest(cmsSignedData);
    }

    /**
     * This method build a group of digests to be covered in case of an external-evidence-record incorporation.
     * Note: the original detached document shall be provided within {@code #setDetachedContent} method.
     *
     * @return a list of {@code Digest}, containing the signature digest on the first position,
     *         and digest of a detached document on the second position
     */
    public List<Digest> buildExternalEvidenceRecordDigest() {
        final CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signatureDocument);
        Digest signatureDigest = getDigest(cmsSignedData);
        Digest originalDocumentDigest = getDigest(detachedDocument);
        return Arrays.asList(signatureDigest, originalDocumentDigest);
    }

    /**
     * Gets digest of {@code cmsSignedData} to be protected by an evidence record
     *
     * @param cmsSignedData {@link CMSSignedData} to cover
     * @return {@link Digest}
     */
    protected Digest getDigest(CMSSignedData cmsSignedData) {
        byte[] messageImprint = getCMSSignedDataMessageImprint(cmsSignedData);
        byte[] digest = DSSUtils.digest(digestAlgorithm, messageImprint);
        return new Digest(digestAlgorithm, digest);
    }

    /**
     * Returns a CMSSignedData's message-imprint to be protected by an evidence record
     *
     * @param cmsSignedData {@link CMSSignedData}
     * @return encoded message-imprint binaries
     */
    protected byte[] getCMSSignedDataMessageImprint(CMSSignedData cmsSignedData) {
        if (parallelEvidenceRecord) {
            cmsSignedData = getCMSSignedDataBeforeLastEvidenceRecord(cmsSignedData);
        }
        /*
         * The ContentInfo instance shall be DER encoded before computing the hash.
         */
        return DSSASN1Utils.getDEREncoded(cmsSignedData);
    }

    /**
     * Creates a CMSSignedData that have been protected by the latest evidence-record
     *
     * @param cmsSignedData {@link CMSSignedData} protected by evidence-record(s)
     * @return original {@link CMSSignedData}
     */
    protected CMSSignedData getCMSSignedDataBeforeLastEvidenceRecord(CMSSignedData cmsSignedData) {
        boolean signerWithERFound = false;
        List<SignerInformation> newSignerInformationList = new ArrayList<>();
        for (SignerInformation signerInformation : cmsSignedData.getSignerInfos().getSigners()) {
            AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
            Attribute latestEvidenceRecordAttribute = getLatestEvidenceRecordAttribute(unsignedAttributes);
            if (latestEvidenceRecordAttribute != null) {
                if (signerWithERFound) {
                    /*
                     * At most one of the SignerInfo instances within the SignedData instance shall contain
                     * evidence-records attributes. If the SignerInfo instance contains more than one
                     * evidence-records attribute, only the ER(s) in the latest added evidence-records
                     * attribute shall be updated.
                     */
                    throw new IllegalInputException("The CMSSignedData contains multiple evidence record attributes! Unable to compute hash.");
                }

                unsignedAttributes = removeAttribute(unsignedAttributes, latestEvidenceRecordAttribute);
                if (unsignedAttributes.size() == 0) {
                    unsignedAttributes = null;
                }
                signerInformation = CMSUtils.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
                signerWithERFound = true;
            }
            newSignerInformationList.add(signerInformation);
        }
        return CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(newSignerInformationList));
    }

    private Attribute getLatestEvidenceRecordAttribute(AttributeTable attributeTable) {
        Attribute latestERAttribute = null;
        if (attributeTable != null) {
            Date latestERProductionDate = null;
            Attribute[] attributes = attributeTable.toASN1Structure().getAttributes();
            if (Utils.isArrayNotEmpty(attributes)) {
                /*
                 * Once an evidence-records attribute is included within a SignedData instance,
                 * the only changes that might be applied to the SignedData instance are the renewal of
                 * the ER within the evidence-records attribute, the adding of a new ER within
                 * a new AttributeValue of the latest evidence record attribute or the adding of
                 * another evidence-records attribute. No other changes shall be applied to the SignedData instance.
                 */
                for (Attribute attribute : attributes) {
                    if (isERAttribute(attribute)) {
                        Date attributeProductionTime = getERAttributeProductionTime(attribute);
                        if (latestERProductionDate == null ||
                                (attributeProductionTime != null && attributeProductionTime.after(latestERProductionDate))) {
                            latestERAttribute = attribute;
                            latestERProductionDate = attributeProductionTime;
                        }
                    }
                }
            }
        }
        return latestERAttribute;
    }

    private boolean isERAttribute(Attribute attribute) {
        return OID.id_aa_er_internal.equals(attribute.getAttrType()) ||
                OID.id_aa_er_external.equals(attribute.getAttrType());
    }

    private Date getERAttributeProductionTime(Attribute attribute) {
        Date earliestProductionTime = null;
        for (ASN1Encodable asn1Encodable : attribute.getAttributeValues()) {
            Date erProductionTime = getERProductionTime(asn1Encodable);
            if (earliestProductionTime == null || erProductionTime.before(earliestProductionTime)) {
                earliestProductionTime = erProductionTime;
            }
        }
        return earliestProductionTime;
    }

    private Date getERProductionTime(ASN1Encodable asn1Encodable) {
        try {
            EvidenceRecord evidenceRecord = EvidenceRecord.getInstance(asn1Encodable);
            if (evidenceRecord == null) {
                throw new IllegalInputException("Unable to build an evidence record!");
            }
            ArchiveTimeStampChain[] archiveTimeStampChains = evidenceRecord.getArchiveTimeStampSequence().getArchiveTimeStampChains();
            if (Utils.isArrayEmpty(archiveTimeStampChains)) {
                throw new IllegalInputException("No archive time-stamp chains found within evidence record!");
            }
            ArchiveTimeStampChain archiveTimeStampChain = archiveTimeStampChains[0];
            ArchiveTimeStamp[] archiveTimestamps = archiveTimeStampChain.getArchiveTimestamps();
            if (Utils.isArrayEmpty(archiveTimestamps)) {
                throw new IllegalInputException("No archive time-stamps found within evidence record!");
            }
            ArchiveTimeStamp archiveTimestamp = archiveTimestamps[0];
            return new TimeStampToken(archiveTimestamp.getTimeStamp()).getTimeStampInfo().getGenTime();

        } catch (TSPException | IOException e) {
            throw new DSSException(String.format("Unable to build embedded time-stamp! Reason : %s", e.getMessage()), e);
        }
    }

    private AttributeTable removeAttribute(AttributeTable attributeTable, Attribute attributeToRemove) {
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        for (Attribute attribute : attributeTable.toASN1Structure().getAttributes()) {
            if (attributeToRemove != attribute) {
                asn1EncodableVector.add(attribute);
            }
        }
        return new AttributeTable(asn1EncodableVector);
    }

}
