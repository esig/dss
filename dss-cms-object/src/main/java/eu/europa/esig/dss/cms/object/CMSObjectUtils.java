package eu.europa.esig.dss.cms.object;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSSignedDocument;
import eu.europa.esig.dss.cms.ICMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;

/**
 * Implements {@code ICMSUtils} using a {@code eu.europa.esig.dss.cms.bc.CMSSignedDataWrapper} processing
 *
 */
public class CMSObjectUtils implements ICMSUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CMSObjectUtils.class);

    /**
     * Default constructor
     */
    public CMSObjectUtils() {
        // empty
    }

    @Override
    public CMS parseToCMS(DSSDocument document) {
        if (document instanceof CMSSignedDocument) {
            return new CMSSignedDataObject(((CMSSignedDocument) document).getCMSSignedData());
        }
        try (InputStream is = document.openStream()) {
            CMSSignedData cmsSignedData = new CMSSignedData(is);
            return new CMSSignedDataObject(cmsSignedData);
        } catch (IOException | CMSException e) {
            throw new DSSException("Not a valid CAdES file", e);
        }
    }

    @Override
    public CMS parseToCMS(byte[] binaries) {
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(binaries);
            return new CMSSignedDataObject(cmsSignedData);
        } catch (CMSException e) {
            throw new DSSException("Not a valid CAdES file", e);
        }
    }

    @Override
    public DSSDocument writeToDSSDocument(CMS cms, DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        // NOTE: the 'dss-cms-object' implementation does not require using of {@code resourcesHandlerBuilder}
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataObject(cms);
        return new CMSSignedDocument(cmsSignedDataObject.getCMSSignedData());
    }

    @Override
    public SignerInformation recomputeSignerInformation(CMS cms, SignerId signerId, DigestCalculatorProvider digestCalculatorProvider,
                                                        DSSResourcesHandlerBuilder resourcesHandlerBuilder) throws CMSException {
        CMSSignedDataParser cmsSignedDataParser = new CMSSignedDataParser(digestCalculatorProvider, cms.getDEREncoded());
        return cmsSignedDataParser.getSignerInfos().get(signerId);
    }

    @Override
    public CMS replaceSigners(CMS cms, SignerInformationStore newSignerStore) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataObject(cms);
        CMSSignedData cmsSignedData = CMSSignedData.replaceSigners(cmsSignedDataObject.getCMSSignedData(), newSignerStore);
        return new CMSSignedDataObject(cmsSignedData);
    }

    @Override
    public CMS replaceCertificatesAndCRLs(CMS cms, Store<X509CertificateHolder> certificates,
                                          Store<X509AttributeCertificateHolder> attributeCertificates,
                                          Store<X509CRLHolder> crls, Store<?> ocspResponsesStore, Store<?> ocspBasicStore) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataObject(cms);
        try {
            Store<Encodable> newCRLStore = toCRLsStore(crls, ocspResponsesStore, ocspBasicStore);
            CMSSignedData cmsSignedData = CMSSignedData.replaceCertificatesAndCRLs(cmsSignedDataObject.getCMSSignedData(),
                    certificates, attributeCertificates, newCRLStore);
            return new CMSSignedDataObject(cmsSignedData);
        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to replace content of CMS SignedData. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Creates a new combined SignedData.crls store containing CRLs, OCSP responses and OCSP Basic responses
     *
     * @param crls {@link Store} containing CRLs
     * @param ocspResponses {@link Store} containing OCSP responses
     * @param ocspBasicResponses {@link Store} containing OCSP Basic responses
     * @return {@link Store}
     */
    public static Store<Encodable> toCRLsStore(Store<X509CRLHolder> crls, Store<?> ocspResponses, Store<?> ocspBasicResponses) {
        final Collection<Encodable> newCrlsStore = new HashSet<>(crls.getMatches(null));
        for (Object ocsp : ocspResponses.getMatches(null)) {
            newCrlsStore.add(new OtherRevocationInfoFormat(CMSObjectIdentifiers.id_ri_ocsp_response, (ASN1Encodable) ocsp));
        }
        for (Object ocsp : ocspBasicResponses.getMatches(null)) {
            newCrlsStore.add(new OtherRevocationInfoFormat(OCSPObjectIdentifiers.id_pkix_ocsp_basic, (ASN1Encodable) ocsp));
        }
        return new CollectionStore<>(newCrlsStore);
    }

    @Override
    public CMS populateDigestAlgorithmSet(CMS cms, Collection<AlgorithmIdentifier> digestAlgorithmsToAdd) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataObject(cms);
        CMSSignedData cmsSignedData = cmsSignedDataObject.getCMSSignedData();
        for (AlgorithmIdentifier asn1ObjectIdentifier : digestAlgorithmsToAdd) {
            if (!cmsSignedData.getDigestAlgorithmIDs().contains(asn1ObjectIdentifier)) {
                cmsSignedData = CMSSignedData.addDigestAlgorithm(cmsSignedData, asn1ObjectIdentifier);
            }
        }
        return new CMSSignedDataObject(cmsSignedData);
    }

    private static CMSSignedDataObject toCMSSignedDataObject(CMS cms) {
        if (cms instanceof CMSSignedDataObject) {
            return (CMSSignedDataObject) cms;
        }
        throw new IllegalStateException("Only CMSSignedDataObject implementation is supported in 'dss-cms-object' module!");
    }

    @Override
    public CMS toCMS(TimeStampToken timeStampToken) {
        return new CMSSignedDataObject(timeStampToken.toCMSSignedData());
    }

    @Override
    public String getContentInfoEncoding(CMS cms) {
        SignedData signedData = getSignedData(cms);
        final ContentInfo content = signedData.getEncapContentInfo();
        if (content.getContent() instanceof BEROctetString) {
            return ASN1Encoding.BER;
        } else if (content.getContent() instanceof DEROctetString) {
            return ASN1Encoding.DER;
        } else {
            throw new UnsupportedOperationException(String.format("The ContentInfo encoding class '%s' is not supported!",
                    content.getContent().getClass().getName()));
        }
    }

    @Override
    public void writeSignedDataDigestAlgorithmsEncoded(CMS cms, OutputStream os) throws IOException {
        SignedData signedData = getSignedData(cms);

        ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
        digestAlgorithms.encodeTo(os);
    }

    @Override
    public void writeContentInfoEncoded(CMS cms, OutputStream os) throws IOException {
        SignedData signedData = getSignedData(cms);

        final ContentInfo content = signedData.getEncapContentInfo();
        byte[] contentInfoBytes;
        if (content.getContent() instanceof BEROctetString) {
            contentInfoBytes = DSSASN1Utils.getBEREncoded(content);
        } else {
            contentInfoBytes = DSSASN1Utils.getDEREncoded(content);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("ContentInfo: {}", DSSUtils.toHex(contentInfoBytes));
        }
        os.write(contentInfoBytes);
    }

    @Override
    public void writeSignedDataCertificatesEncoded(CMS cms, OutputStream os) throws IOException {
        SignedData signedData = getSignedData(cms);

        byte[] certificatesBytes;

        final ASN1Set certificates = signedData.getCertificates();
        if (certificates != null) {
            /*
             * In order to calculate correct message imprint it is important
             * to use the correct encoding.
             */
            try {
                if (certificates instanceof BERSet) {
                    certificatesBytes = new BERTaggedObject(false, 0, new BERSequence(certificates.toArray())).getEncoded();
                } else {
                    certificatesBytes = new DERTaggedObject(false, 0, new DERSequence(certificates.toArray())).getEncoded();
                }

            } catch (IOException e) {
                throw new DSSException(String.format("An error occurred on reading SignedData.certificates field : %s", e.getMessage()), e);
            }
			if (LOG.isTraceEnabled()) {
                LOG.trace("Certificates: {}", DSSUtils.toHex(certificatesBytes));
			}
            os.write(certificatesBytes);

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Certificates are not present in the SignedData.");
            }
        }

    }

    @Override
    public void writeSignedDataCRLsEncoded(CMS cms, OutputStream os) throws IOException {
        SignedData signedData = getSignedData(cms);

        byte[] crlBytes;

        final ASN1Set crLs = signedData.getCRLs();
        if (crLs != null) {
            try {
                if (signedData.getCRLs() instanceof BERSet) {
                    crlBytes = new BERTaggedObject(false, 1, new BERSequence(crLs.toArray())).getEncoded();
                } else {
                    crlBytes = new DERTaggedObject(false, 1, new DERSequence(crLs.toArray())).getEncoded();
                }

            } catch (IOException e) {
                throw new DSSException(String.format("An error occurred on reading SignedData.crls field : %s", e.getMessage()), e);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("CRLs: {}", DSSUtils.toHex(crlBytes));
            }
            os.write(crlBytes);

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CRLs are not present in the SignedData.");
            }
        }
    }

    @Override
    public void writeSignedDataSignerInfosEncoded(CMS cms, OutputStream os) throws IOException {
        SignedData signedData = getSignedData(cms);

        byte[] signerInfosBytes;

        SignerInformationStore signerInfos = cms.getSignerInfos();
        if (signerInfos != null) {
            try {
                ASN1EncodableVector signerInfosVector = new ASN1EncodableVector();
                for (SignerInformation signerInformation : cms.getSignerInfos()) {
                    signerInfosVector.add(signerInformation.toASN1Structure());
                }

                if (signedData.getSignerInfos() instanceof BERSet) {
                    signerInfosBytes = new BERSet(signerInfosVector).getEncoded();
                } else {
                    signerInfosBytes = new DERSet(signerInfosVector).getEncoded();
                }

            } catch (IOException e) {
                throw new DSSException(String.format("An error occurred on reading SignedData.signerInfos field : %s", e.getMessage()), e);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("SignerInfos: {}", DSSUtils.toHex(signerInfosBytes));
            }
            os.write(signerInfosBytes);

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SignerInfos are not present in the SignedData.");
            }
        }
    }

    /**
     * Gets SignedData element of the CMS
     *
     * @param cms {@link CMS}
     * @return {@link SignedData}
     */
    public static SignedData getSignedData(CMS cms) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataObject(cms);
        final ContentInfo contentInfo = cmsSignedDataObject.getCMSSignedData().toASN1Structure();
        return SignedData.getInstance(contentInfo.getContent());
    }

    @Override
    public CMSTypedData toCMSEncapsulatedContent(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be signed is missing");
        CMSTypedData content;
        if (document instanceof DigestDocument) {
            content = new CMSAbsentContent();
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
        throw new UnsupportedOperationException("Usage of DSSResourcesHandlerBuilder is not supported within " +
                "the 'dss-cms-object' module! Remove the setter to use in-memory processing, or switch to " +
                "'dss-cms-stream' implementation.");
    }

    @Override
    public SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation, AttributeTable unsignedAttributes) {
        return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
    }

    @Override
    public void assertATSv2AugmentationSupported() {
        // supported, do nothing
    }

}
