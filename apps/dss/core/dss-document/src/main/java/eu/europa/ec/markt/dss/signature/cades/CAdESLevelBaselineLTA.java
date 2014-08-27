/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.cades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;

/**
 * This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
 * id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
 * <p/>
 * "If the certificate-values and revocation-values attributes are not present in the CAdES-BES or CAdES-EPES, then they
 * shall be added to the electronic signature prior to computing the archive time-stamp token." is the reason we extend
 * from the XL profile.
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class CAdESLevelBaselineLTA extends CAdESSignatureExtension {

    private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineLTA.class);

    private final CAdESLevelBaselineLT cadesProfileLT;
    private final CertificateVerifier certificateVerifier;

    public CAdESLevelBaselineLTA(TSPSource signatureTsa, CertificateVerifier certificateVerifier, boolean onlyLastSigner) {
        super(signatureTsa, onlyLastSigner);
        cadesProfileLT = new CAdESLevelBaselineLT(signatureTsa, certificateVerifier, onlyLastSigner);
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, SignatureParameters parameters) {
        return cadesProfileLT.extendCMSSignatures(cmsSignedData, parameters);
    }

    @Override
    protected SignerInformation extendCMSSignature(final CMSSignedData cmsSignedData, SignerInformation signerInformation,
                                                   final SignatureParameters parameters) throws DSSException {

        CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
	    cadesSignature.setDetachedContents(parameters.getDetachedContent());
        AttributeTable unsignedAttributes = CAdESSignature.getUnsignedAttributes(signerInformation);
        unsignedAttributes = addArchiveTimestampV3Attribute(cadesSignature, cmsSignedData, signerInformation, parameters, unsignedAttributes);
        SignerInformation newSignerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
        return newSignerInformation;
    }

    /**
     * The input for the archive-time-stamp-v3’s message imprint computation shall be the concatenation (in the
     * order shown by the list below) of the signed data hash (see bullet 2 below) and certain fields in their binary encoded
     * form without any modification and including the tag, length and value octets:
     * <ol>
     * <li>The SignedData.encapContentInfo.eContentType.
     * <li>The octets representing the hash of the signed data. The hash is computed on the same content that was used
     * for computing the hash value that is encapsulated within the message-digest signed attribute of the
     * CAdES signature being archive-time-stamped. The hash algorithm applied shall be the same as the hash
     * algorithm used for computing the archive time-stamp’s message imprint. The inclusion of the hash algorithm
     * in the SignedData.digestAlgorithms set is recommended.
     * <li>Fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and
     * signature within the SignedData.signerInfos’s item corresponding to the signature being archive
     * time-stamped, in their order of appearance.
     * <li>A single instance of ATSHashIndex type (created as specified in clause 6.4.2).
     * </ol>
     *
     * @param cadesSignature
     * @param cmsSignedData
     * @param signerInformation
     * @param parameters
     * @param unsignedAttributes
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    private AttributeTable addArchiveTimestampV3Attribute(CAdESSignature cadesSignature, CMSSignedData cmsSignedData, SignerInformation signerInformation,
                                                          SignatureParameters parameters, AttributeTable unsignedAttributes) throws DSSException {
        final CadesLevelBaselineLTATimestampExtractor cadesLevelBaselineLTATimestampExtractor = new CadesLevelBaselineLTATimestampExtractor();
        final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
        final Attribute atsHashIndexAttribute = cadesLevelBaselineLTATimestampExtractor.getAtsHashIndex(signerInformation, timestampDigestAlgorithm, cadesSignature);

        final byte[] originalDocumentBytes = getOriginalDocumentBytes(cmsSignedData, parameters);

        final byte[] encodedToTimestamp = cadesLevelBaselineLTATimestampExtractor
              .getArchiveTimestampDataV3(cadesSignature, signerInformation, atsHashIndexAttribute, originalDocumentBytes, parameters.getSignatureTimestampParameters().getDigestAlgorithm());

        final ASN1Object timeStampAttributeValue = getTimeStampAttributeValue(signatureTsa, encodedToTimestamp, timestampDigestAlgorithm, atsHashIndexAttribute);

        final AttributeTable newUnsignedAttributes = unsignedAttributes.add(OID.id_aa_ets_archiveTimestampV3, timeStampAttributeValue);
        return newUnsignedAttributes;
    }

    /**
     * Returns the original document which is signed, either from cmsSignedData if possible, or from parameters.getOriginalDocument
     *
     * @param cmsSignedData
     * @param parameters
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    private byte[] getOriginalDocumentBytes(CMSSignedData cmsSignedData, SignatureParameters parameters) throws DSSException {

        try {

            final ByteArrayOutputStream originalSignedFileByteArrayOutputStream = new ByteArrayOutputStream();
            if (cmsSignedData.getSignedContent() != null) {
                cmsSignedData.getSignedContent().write(originalSignedFileByteArrayOutputStream);
            } else {
                originalSignedFileByteArrayOutputStream.write(parameters.getDetachedContent().getBytes());
            }
            return originalSignedFileByteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new DSSException(e);
        } catch (CMSException e) {
            throw new DSSException(e);
        }
    }
}
