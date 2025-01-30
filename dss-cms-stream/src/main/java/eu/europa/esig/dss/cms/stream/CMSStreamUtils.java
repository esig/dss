package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.ICMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

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
    public CMS replaceSigners(CMS cms, SignerInformationStore newSignerStore) {
        CMSSignedDataStream cmsSignedDataStream = toCMSSignedDataStream(cms);
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

    @Override
    public CMS toCMS(TimeStampToken timeStampToken) {
        try {
            return CMSStreamDocumentParser.fromBinaries(timeStampToken.getEncoded());
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read TimeStampToken binaries : %s", e.getMessage()), e);
        }
    }

    @Override
    public byte[] getContentInfoEncoded(CMS cms) {
        // TODO : implement
        throw new UnsupportedOperationException("archive-time-stamp-v2 processing is not supported for 'dss-cms-stream' module!");
    }

    @Override
    public byte[] getSignedDataCertificatesEncoded(CMS cms) {
        throw new UnsupportedOperationException("archive-time-stamp-v2 processing is not supported for 'dss-cms-stream' module!");
    }

    @Override
    public byte[] getSignedDataCRLsEncoded(CMS cms) {
        throw new UnsupportedOperationException("archive-time-stamp-v2 processing is not supported for 'dss-cms-stream' module!");
    }

    private static CMSSignedDataStream toCMSSignedDataStream(CMS cms) {
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

}
