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

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESAttributeOrderComparator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CAdESUnsignedAttributes;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.validation.evidencerecord.AbstractSignatureEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.util.ArrayList;
import java.util.Arrays;
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
     * Sets whether the signature shall be DER-encoded for a hash computation (as per ETSI TS 119 122-3 v1.1.1)
     */
    protected boolean derEncoded;

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
     * Constructor to instantiate CAdESEvidenceRecordDigestBuilder from a {@code signature}
     * for the given {@code evidenceRecordAttribute}.
     * This constructor is used on validation of existing evidence record.
     *
     * @param signature {@link AdvancedSignature} containing the incorporated evidence record
     * @param evidenceRecordAttribute {@link SignatureAttribute} location of the evidence record
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     */
    protected CAdESEvidenceRecordDigestBuilder(final AdvancedSignature signature, final SignatureAttribute evidenceRecordAttribute,
                                               final DigestAlgorithm digestAlgorithm) {
        super(signature, evidenceRecordAttribute, digestAlgorithm);
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

    /**
     * Sets whether a signature shall be DER-encoded prior to the hash computation
     *
     * @param derEncoded whether signature shall be DER encoded
     * @return this builder
     */
    public CAdESEvidenceRecordDigestBuilder setDEREncoded(boolean derEncoded) {
        this.derEncoded = derEncoded;
        return this;
    }

    @Override
    public CAdESEvidenceRecordDigestBuilder setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        return (CAdESEvidenceRecordDigestBuilder) super.setParallelEvidenceRecord(parallelEvidenceRecord);
    }

    @Override
    public Digest build() {
        final CMS cms = getCMS();
        return getDigest(cms);
    }

    /**
     * This method build a group of digests to be covered in case of an external-evidence-record incorporation.
     * Note: the original detached document shall be provided within {@code #setDetachedContent} method.
     *
     * @return a list of {@code Digest}, containing the signature digest on the first position,
     *         and digest of a detached document on the second position
     */
    public List<Digest> buildExternalEvidenceRecordDigest() {
        final CMS cms = getCMS();
        Digest signatureDigest = getDigest(cms);
        Digest originalDocumentDigest = getDigest(detachedDocument);
        return Arrays.asList(signatureDigest, originalDocumentDigest);
    }

    /**
     * Gets a CMS
     *
     * @return {@link CMS}
     */
    protected CMS getCMS() {
        if (signature != null) {
            return ((CAdESSignature) signature).getCMS();
        } else if (signatureDocument != null) {
            return CMSUtils.parseToCMS(signatureDocument);
        } else {
            throw new IllegalStateException("Either a signature or a signature document shall be provided!");
        }
    }

    /**
     * Gets digest of {@code cms} to be protected by an evidence record
     *
     * @param cms {@link CMS} to cover
     * @return {@link Digest}
     */
    protected Digest getDigest(CMS cms) {
        byte[] messageImprint = getCMSContentInfoMessageImprint(cms);
        byte[] digest = DSSUtils.digest(digestAlgorithm, messageImprint);
        return new Digest(digestAlgorithm, digest);
    }

    /**
     * Returns a CMSSignedData's message-imprint to be protected by an evidence record
     *
     * @param cms {@link CMSSignedData}
     * @return encoded message-imprint binaries
     */
    protected byte[] getCMSContentInfoMessageImprint(CMS cms) {
        if (parallelEvidenceRecord || signature != null) {
            cms = getCMSSignedDataBeforeLastEvidenceRecord(cms);
        }
        /*
         * ETSI TS 119 122-3 requires the CMS ContentInfo to be DER encoded,
         * while RFC 4998 uses the original CMS encoding.
         * We need to provide a way to compute digest using the specified encoding.
         */
        return getEncoded(cms);
    }

    /**
     * Creates a CMS that have been protected by the latest evidence-record
     *
     * @param cms {@link CMS} protected by evidence-record(s)
     * @return original {@link CMS}
     */
    protected CMS getCMSSignedDataBeforeLastEvidenceRecord(CMS cms) {
        boolean signerWithERFound = false;
        List<SignerInformation> newSignerInformationList = new ArrayList<>();
        for (SignerInformation signerInformation : cms.getSignerInfos().getSigners()) {
            if (signature == null || ((CAdESSignature) signature).getSignerInformation() == signerInformation) {
                CAdESUnsignedAttributes unsignedAttributes = CAdESUnsignedAttributes.build(signerInformation);

                CAdESAttribute targetEvidenceRecordAttribute;
                if (parallelEvidenceRecord) {
                    targetEvidenceRecordAttribute = getLatestEvidenceRecordAttribute(unsignedAttributes);
                } else if (evidenceRecordAttribute != null) {
                    targetEvidenceRecordAttribute = (CAdESAttribute) evidenceRecordAttribute;
                } else {
                    throw new IllegalStateException("Evidence record attribute cannot be null!");
                }

                if (targetEvidenceRecordAttribute != null) {
                    if (signerWithERFound) {
                        /*
                         * At most one of the SignerInfo instances within the SignedData instance shall contain
                         * evidence-records attributes. If the SignerInfo instance contains more than one
                         * evidence-records attribute, only the ER(s) in the latest added evidence-records
                         * attribute shall be updated.
                         */
                        throw new IllegalInputException("The CMSSignedData contains multiple evidence record attributes! Unable to compute hash.");
                    }

                    AttributeTable unsignedAttributesTable = removeAttributesAtAndAfter(unsignedAttributes, targetEvidenceRecordAttribute);
                    if (unsignedAttributesTable.size() == 0) {
                        unsignedAttributesTable = null;
                    }
                    signerInformation = CMSUtils.replaceUnsignedAttributes(signerInformation, unsignedAttributesTable);

                    if (parallelEvidenceRecord) {
                        signerWithERFound = true;
                    }
                }
            }
            newSignerInformationList.add(signerInformation);
        }
        return CMSUtils.replaceSigners(cms, new SignerInformationStore(newSignerInformationList));
    }

    private CAdESAttribute getLatestEvidenceRecordAttribute(CAdESUnsignedAttributes unsignedAttributes) {
        if (unsignedAttributes != null) {
            List<CAdESAttribute> attributes = unsignedAttributes.getAttributes(); // returns sorted
            if (Utils.isCollectionNotEmpty(attributes)) {
                /*
                 * Once an evidence-records attribute is included within a SignedData instance,
                 * the only changes that might be applied to the SignedData instance are the renewal of
                 * the ER within the evidence-records attribute, the adding of a new ER within
                 * a new AttributeValue of the latest evidence record attribute or the adding of
                 * another evidence-records attribute. No other changes shall be applied to the SignedData instance.
                 */
                CAdESAttribute lastAttribute = attributes.get(attributes.size() - 1);
                if (lastAttribute.isEvidenceRecord()) {
                    return lastAttribute;
                }
            }
        }
        return null;
    }

    private AttributeTable removeAttributesAtAndAfter(CAdESUnsignedAttributes unsignedAttributes, CAdESAttribute unsignedAttribute) {
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();

        final List<CAdESAttribute> attributesList = new ArrayList<>();
        for (CAdESAttribute attribute : unsignedAttributes.getAttributes()) {
            if (unsignedAttribute.equals(attribute)) {
                break; // break if the target attribute is reached
            }
            attributesList.add(attribute);
        }

        if (Utils.isCollectionNotEmpty(attributesList)) {
            // ensure the original order
            attributesList.sort(new CAdESAttributeOrderComparator());
            attributesList.forEach(a -> asn1EncodableVector.add(new Attribute(a.getASN1Oid(), a.getAttrValues())));
        }

        return new AttributeTable(asn1EncodableVector);
    }

    /**
     * Gets encoded CMS binaries
     *
     * @param cms {@link CMS}
     * @return byte array
     */
    protected byte[] getEncoded(CMS cms) {
        if (derEncoded) {
            return cms.getDEREncoded();
        } else {
            return cms.getEncoded();
        }
    }

}
