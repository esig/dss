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
package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.ICMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.PKCS7TypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * CMS Utils using a stream processing of a CMS SignedData
 *
 */
public class CMSStreamUtils implements ICMSUtils {

    /**
     * Default constructor
     */
    public CMSStreamUtils() {
        // empty
    }

    @Override
    public CMS parseToCMS(DSSDocument document) {
        return CMSStreamDocumentParser.fromDSSDocument(document);
    }

    @Override
    public CMS parseToCMS(byte[] binaries) {
        return CMSStreamDocumentParser.fromBinaries(binaries);
    }

    @Override
    public DSSDocument writeToDSSDocument(CMS cms, DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        Objects.requireNonNull(resourcesHandlerBuilder, "DSSResourcesHandlerBuilder shall be provided!");
        return new CMSStreamDocumentBuilder()
                .setResourcesHandlerBuilder(resourcesHandlerBuilder)
                .createCMSSignedDocument(cms);
    }

    @Override
    public SignerInformation recomputeSignerInformation(CMS cms, SignerId signerId, DigestCalculatorProvider digestCalculatorProvider,
                                                        DSSResourcesHandlerBuilder resourcesHandlerBuilder) throws CMSException {
        return new CMSStreamDocumentBuilder()
                .setResourcesHandlerBuilder(resourcesHandlerBuilder)
                .recreateSignerInformationStore(cms, digestCalculatorProvider)
                .get(signerId);
    }

    @Override
    public CMS replaceSigners(CMS cms, SignerInformationStore newSignerStore) {
        CMSSignedDataStream cmsSignedDataStream = createCopy(toCMSSignedDataStream(cms));
        cmsSignedDataStream.setSignerInfos(newSignerStore);
        return cmsSignedDataStream;
    }

    @Override
    public CMS replaceCertificatesAndCRLs(CMS cms, Store<X509CertificateHolder> certificates,
                                          Store<X509AttributeCertificateHolder> attributeCertificates,
                                          Store<X509CRLHolder> crls, Store<?> ocspResponsesStore, Store<?> ocspBasicStore) {
        CMSSignedDataStream cmsSignedDataStream = toCMSSignedDataStream(cms);
        cmsSignedDataStream.setCertificates(certificates);
        cmsSignedDataStream.setAttributeCertificates(attributeCertificates);
        cmsSignedDataStream.setCRLs(crls);
        cmsSignedDataStream.setOcspResponseStore(ocspResponsesStore);
        cmsSignedDataStream.setOcspBasicStore(ocspBasicStore);
        return cmsSignedDataStream;
    }

    @Override
    public CMS populateDigestAlgorithmSet(CMS cms, Collection<AlgorithmIdentifier> digestAlgorithmsToAdd) {
        CMSSignedDataStream cmsSignedDataStream = toCMSSignedDataStream(cms);
        Set<AlgorithmIdentifier> result = new HashSet<>(cms.getDigestAlgorithmIDs());
        result.addAll(digestAlgorithmsToAdd);
        cmsSignedDataStream.setDigestAlgorithmIDs(result);
        return cmsSignedDataStream;
    }

    /**
     * Creates a copy of the {@code CMS} object
     *
     * @param cms {@link CMS}
     * @return {@link CMS}
     */
    public CMSSignedDataStream createCopy(CMS cms) {
       return new CMSSignedDataStream(toCMSSignedDataStream(cms));
    }

    @Override
    public CMS toCMS(TimeStampToken timeStampToken) {
        try {
            return CMSStreamDocumentParser.fromBinaries(timeStampToken.getEncoded());
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read TimeStampToken binaries : %s", e.getMessage()), e);
        }
    }

    @Override
    public String getContentInfoEncoding(CMS cms) {
        /*
         * In this method we check for available data object to evaluate encoding of SignedData.
         * It is expected that all content of SignedData uses the same encoding.
         * We cannot evaluate directly on the parser, as BC uses package-private and/or deprecated classes.
         * Therefore, we extract the data from SignedData.digestAlgorithms, as it is mandatory field and
         * there is no possibility to encounter a large data like an encapsulated ContentInfo.
         */
        DSSDocument cmsDocument = getCMSDocument(cms);
        try (InputStream is = cmsDocument.openStream()) {
            ASN1StreamParser in = new ASN1StreamParser(is);
            ASN1SequenceParser seqParser = (ASN1SequenceParser) in.readObject();

            // TODO : BERSequenceParser is deprecated, we should avoid using it for now
            // return seqParser instanceof BERSequenceParser;

            ContentInfoParser contentInfoParser = new ContentInfoParser(seqParser);
            SignedDataParser signedDataParser = SignedDataParser.getInstance(contentInfoParser.getContent(BERTags.SEQUENCE));

            ASN1SetParser digestAlgorithms = signedDataParser.getDigestAlgorithms();
            flush(digestAlgorithms);

            ContentInfoParser encapContentInfo = signedDataParser.getEncapContentInfo();
            flush(encapContentInfo);

            ASN1SetParser certificatesParser = signedDataParser.getCertificates();
            if (certificatesParser != null) {
                if (certificatesParser.toASN1Primitive() instanceof BERSet) {
                    return ASN1Encoding.BER;
                } else if (certificatesParser.toASN1Primitive() instanceof DERSet) {
                    return ASN1Encoding.DER;
                } else if (certificatesParser.toASN1Primitive() instanceof DLSet) {
                    return ASN1Encoding.DL;
                } else {
                    throw new UnsupportedOperationException(String.format("The ContentInfo encoding class '%s' is not supported!", 
                            certificatesParser.toASN1Primitive().getClass().getName()));
                }
            }

            throw new UnsupportedOperationException("No SignedData.certificates found! Unable to determine encoding of the SingedData.");

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read CMS document stream : %s", e.getMessage()), e);
        }
    }

    /**
     * Writes the encoded binaries of the SignedData.digestAlgorithms field to the given {@code OutputStream}
     * NOTE: This method is used for evidence record hash computation
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public void writeSignedDataDigestAlgorithmsEncoded(CMS cms, OutputStream os) throws IOException {
        DSSDocument cmsDocument = getCMSDocument(cms);
        // we need to preserve the original order, that is why we extract the original set of certificates
        ASN1Set digestAlgorithms = getSignedDataDigestAlgorithms(cmsDocument);
        if (digestAlgorithms == null) {
            return;
        }
        digestAlgorithms.encodeTo(os);
    }

    private ASN1Set getSignedDataDigestAlgorithms(DSSDocument cmsDocument) {
        // TODO : temp handling, try to cache the original set on parsing
        try (InputStream is = cmsDocument.openStream()) {
            ASN1StreamParser in = new ASN1StreamParser(is);
            ASN1SequenceParser seqParser = (ASN1SequenceParser) in.readObject();

            ContentInfoParser contentInfoParser = new ContentInfoParser(seqParser);
            SignedDataParser signedDataParser = SignedDataParser.getInstance(contentInfoParser.getContent(BERTags.SEQUENCE));

            ASN1SetParser digestAlgorithms = signedDataParser.getDigestAlgorithms();
            if (digestAlgorithms != null) {
                return ASN1Set.getInstance(digestAlgorithms.toASN1Primitive());
            }
            return null;

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read CMS document stream : %s", e.getMessage()), e);
        }
    }

    @Override
    public void writeContentInfoEncoded(CMS cms, OutputStream os) throws IOException {
        if (isBEREncodedContentInfo(cms)) {
            BERSequenceGenerator sequenceGenerator = new BERSequenceGenerator(os);
            sequenceGenerator.addObject(cms.getSignedContentType());
            if (cms.getSignedContent() != null) {
                BEROctetStringGenerator berOctetStringGenerator = new BEROctetStringGenerator(os, 0, true);
                try (OutputStream berOS = berOctetStringGenerator.getOctetOutputStream()) {
                    CMSTypedData cmsTypedData = toCMSEncapsulatedContent(cms.getSignedContent());
                    cmsTypedData.write(berOS);

                } catch (CMSException e) {
                    throw new DSSException(String.format("Unable to write CMS signedContent: %s", e.getMessage()), e);
                }
            }
            sequenceGenerator.close();

        } else {
            DERSequenceGenerator sequenceGenerator = new DERSequenceGenerator(os);
            sequenceGenerator.addObject(cms.getSignedContentType());
            if (cms.getSignedContent() != null) {
                DERSequenceGenerator contentGenerator = new DERSequenceGenerator(sequenceGenerator.getRawOutputStream(), 0, false);
                // TODO : did not find streaming possibility for DER encoding. Implement own DEROctetStringGenerator ?
                byte[] signedContentBytes = DSSUtils.toByteArray(cms.getSignedContent());
                contentGenerator.addObject(new DEROctetString(signedContentBytes));
                contentGenerator.close();
            }
            sequenceGenerator.close();
        }
    }

    private boolean isBEREncodedContentInfo(CMS cms) {
        String contentInfoEncoding = getContentInfoEncoding(cms);
        return ASN1Encoding.BER.equals(contentInfoEncoding);
    }

    @Override
    public void writeSignedDataCertificatesEncoded(CMS cms, OutputStream os) throws IOException {
        DSSDocument cmsDocument = getCMSDocument(cms);
        // we need to preserve the original order, that is why we extract the original set of certificates
        ASN1Set certificates = getSignedDataCertificates(cmsDocument);
        if (certificates == null) {
            return;
        }
        if (certificates instanceof BERSet) {
            BERSequenceGenerator sequenceGenerator = new BERSequenceGenerator(os, 0, false);
            for (ASN1Encodable certificate : certificates.toArray()) {
                sequenceGenerator.addObject(certificate);
            }
            sequenceGenerator.close();

        } else {
            DERSequenceGenerator sequenceGenerator = new DERSequenceGenerator(os, 0, false);
            for (ASN1Encodable certificate : certificates.toArray()) {
                sequenceGenerator.addObject(certificate);
            }
            sequenceGenerator.close();
        }
    }

    private ASN1Set getSignedDataCertificates(DSSDocument cmsDocument) {
        // TODO : temp handling, try to cache the original set on parsing
        try (InputStream is = cmsDocument.openStream()) {
            ASN1StreamParser in = new ASN1StreamParser(is);
            ASN1SequenceParser seqParser = (ASN1SequenceParser) in.readObject();

            ContentInfoParser contentInfoParser = new ContentInfoParser(seqParser);
            SignedDataParser signedDataParser = SignedDataParser.getInstance(contentInfoParser.getContent(BERTags.SEQUENCE));

            ASN1SetParser digestAlgorithms = signedDataParser.getDigestAlgorithms();
            flush(digestAlgorithms);

            ContentInfoParser encapContentInfo = signedDataParser.getEncapContentInfo();
            flush(encapContentInfo);

            ASN1SetParser certificatesParser = signedDataParser.getCertificates();
            if (certificatesParser != null) {
                return ASN1Set.getInstance(certificatesParser.toASN1Primitive());
            }
            return null;

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read CMS document stream : %s", e.getMessage()), e);
        }
    }

    private void flush(ASN1SetParser parser) {
        if (parser != null) {
            parser.toASN1Primitive();
        }
    }

    private void flush(ContentInfoParser encapContentInfo) throws IOException {
        ASN1Encodable contentParser = encapContentInfo.getContent(BERTags.OCTET_STRING);
        if (contentParser instanceof ASN1OctetStringParser) {
            ASN1OctetStringParser octs = (ASN1OctetStringParser) contentParser;
            CMSTypedStream ctStr = new CMSTypedStream(encapContentInfo.getContentType(), octs.getOctetStream());
            ctStr.drain();

        } else if (contentParser != null) {
            PKCS7TypedStream pkcs7Stream = new PKCS7TypedStream(encapContentInfo.getContentType(), contentParser);
            pkcs7Stream.drain();
        }
    }

    @Override
    public void writeSignedDataCRLsEncoded(CMS cms, OutputStream os) throws IOException {
        DSSDocument cmsDocument = getCMSDocument(cms);
        // we need to preserve the original order, that is why we extract the original set of certificates
        ASN1Set crls = getSignedDataCRLs(cmsDocument);
        if (crls == null) {
            return;
        }
        if (crls instanceof BERSet) {
            BERSequenceGenerator sequenceGenerator = new BERSequenceGenerator(os, 1, false);
            for (ASN1Encodable certificate : crls.toArray()) {
                sequenceGenerator.addObject(certificate);
            }
            sequenceGenerator.close();

        } else {
            DERSequenceGenerator sequenceGenerator = new DERSequenceGenerator(os, 1, false);
            for (ASN1Encodable certificate : crls.toArray()) {
                sequenceGenerator.addObject(certificate);
            }
            sequenceGenerator.close();
        }
    }

    private ASN1Set getSignedDataCRLs(DSSDocument cmsDocument) {
        // TODO : temp handling, try to cache the original set on parsing
        try (InputStream is = cmsDocument.openStream()) {
            ASN1StreamParser in = new ASN1StreamParser(is);
            ASN1SequenceParser seqParser = (ASN1SequenceParser) in.readObject();

            ContentInfoParser contentInfoParser = new ContentInfoParser(seqParser);
            SignedDataParser signedDataParser = SignedDataParser.getInstance(contentInfoParser.getContent(BERTags.SEQUENCE));

            ASN1SetParser digestAlgorithms = signedDataParser.getDigestAlgorithms();
            flush(digestAlgorithms);

            ContentInfoParser encapContentInfo = signedDataParser.getEncapContentInfo();
            flush(encapContentInfo);

            ASN1SetParser certificatesParser = signedDataParser.getCertificates();
            flush(certificatesParser);

            ASN1SetParser crlsParser = signedDataParser.getCrls();
            if (crlsParser != null) {
                return ASN1Set.getInstance(crlsParser.toASN1Primitive());
            }
            return null;

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read CMS document stream : %s", e.getMessage()), e);
        }
    }

    /**
     * Writes the encoded binaries of the SignedData.signerInfos field to the given {@code OutputStream}
     * NOTE: This method is used for evidence record hash computation
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public void writeSignedDataSignerInfosEncoded(CMS cms, OutputStream os) throws IOException {
        DSSDocument cmsDocument = getCMSDocument(cms);
        // we need to preserve the original order, that is why we extract the original set of certificates
        ASN1Set signerInfos = getSignedDataSignerInfos(cmsDocument);
        if (signerInfos == null) {
            return;
        }

        ASN1EncodableVector signerInfosVector = new ASN1EncodableVector();
        for (SignerInformation signerInformation : cms.getSignerInfos()) {
            signerInfosVector.add(signerInformation.toASN1Structure());
        }

        if (signerInfos instanceof BERSet) {
            BERSet berSet = new BERSet(signerInfosVector);
            berSet.encodeTo(os);

        } else if (signerInfos instanceof DLSet) {
            DLSet dlSet = new DLSet(signerInfosVector);
            dlSet.encodeTo(os);

        } else if (signerInfos instanceof DERSet) {
            DERSet derSet = new DERSet(signerInfosVector);
            derSet.encodeTo(os);

        } else {
            throw new UnsupportedOperationException(
                    String.format("Unsupported SignerInfos type : %s", signerInfos.getClass().getName()));
        }
    }

    private ASN1Set getSignedDataSignerInfos(DSSDocument cmsDocument) {
        try (InputStream is = cmsDocument.openStream()) {
            ASN1StreamParser in = new ASN1StreamParser(is);
            ASN1SequenceParser seqParser = (ASN1SequenceParser) in.readObject();

            ContentInfoParser contentInfoParser = new ContentInfoParser(seqParser);
            SignedDataParser signedDataParser = SignedDataParser.getInstance(contentInfoParser.getContent(BERTags.SEQUENCE));

            ASN1SetParser digestAlgorithms = signedDataParser.getDigestAlgorithms();
            flush(digestAlgorithms);

            ContentInfoParser encapContentInfo = signedDataParser.getEncapContentInfo();
            flush(encapContentInfo);

            ASN1SetParser certificatesParser = signedDataParser.getCertificates();
            flush(certificatesParser);

            ASN1SetParser crlsParser = signedDataParser.getCrls();
            flush(crlsParser);

            ASN1SetParser signerInfos = signedDataParser.getSignerInfos();
            if (signerInfos != null) {
                return ASN1Set.getInstance(signerInfos.toASN1Primitive());
            }
            return null;

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read CMS document stream : %s", e.getMessage()), e);
        }
    }

    private CMSSignedDataStream toCMSSignedDataStream(CMS cms) {
        if (cms instanceof CMSSignedDataStream) {
            return (CMSSignedDataStream) cms;
        }
        throw new IllegalStateException("Only CMSSignedDataStream implementation is supported in 'dss-cms-stream' module!");
    }

    @Override
    public CMSTypedData toCMSEncapsulatedContent(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be signed is missing");
        CMSTypedData content;
        if (document instanceof DigestDocument) {
            content = new CMSAbsentContent();
        } else if (document instanceof CMSSignedContentDocument) {
            CMSSignedContentDocument cmsSignedContentDocument = (CMSSignedContentDocument) document;
            content = cmsSignedContentDocument.toCMSTypedData();
        } else if (document instanceof FileDocument) {
            FileDocument fileDocument = (FileDocument) document;
            content = new CMSProcessableFile(fileDocument.getFile());
        } else {
            content = new CMSProcessableByteArray(DSSUtils.toByteArray(document));
        }
        return content;
    }

    @Override
    public DSSResourcesHandlerBuilder getDSSResourcesHandlerBuilder(DSSResourcesHandlerBuilder dssResourcesHandlerBuilder) {
        Objects.requireNonNull(dssResourcesHandlerBuilder, "DSSResourcesHandlerBuilder cannot be null!");
        return dssResourcesHandlerBuilder;
    }

    @Override
    public SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation, AttributeTable unsignedAttributes) {
        // copies all information, including resultDigest (not available in BC's {@code SignerInformation.replaceUnsignedAttributes} method)
        // NOTE: this code is moved to 'dss-cms-stream', but could be used globally

        ASN1Set unsignedAttr = null;
        if (unsignedAttributes != null) {
            unsignedAttr = new DERSet(unsignedAttributes.toASN1EncodableVector());
        }

        SignerInfo originalSignerInfo = signerInformation.toASN1Structure();
        SignerInfo extendedSignerInfo = new SignerInfo(originalSignerInfo.getSID(), originalSignerInfo.getDigestAlgorithm(),
                originalSignerInfo.getAuthenticatedAttributes(), originalSignerInfo.getDigestEncryptionAlgorithm(),
                originalSignerInfo.getEncryptedDigest(), unsignedAttr);

        return new SignerInformation(signerInformation, extendedSignerInfo) {};
    }

    private DSSDocument getCMSDocument(CMS cms) {
        CMSSignedDataStream cmsSignedDataStream = toCMSSignedDataStream(cms);
        DSSDocument cmsDocument = cmsSignedDataStream.getCMSDocument();
        if (cmsDocument == null) {
            throw new IllegalStateException("#isBEREncodedSignedData is applicable only for CMSSignedDataStream " +
                    "created based on original CMS document!");
        }
        return cmsDocument;
    }

    @Override
    public void assertATSv2AugmentationSupported() {
        throw new UnsupportedOperationException("Augmentation of CMS signatures with archive-time-stamp-v2 is not " +
                "supported by 'dss-cms-stream' implementation! Please switch to 'dss-cms-object' if support is required.");
    }

    @Override
    public void assertEvidenceRecordEmbeddingSupported() {
        throw new UnsupportedOperationException("Embedding of Evidence Record is not supported by the dss-cms-stream implementation! " +
                "Please switch to 'dss-cms-object' if support is required.");
    }

}
