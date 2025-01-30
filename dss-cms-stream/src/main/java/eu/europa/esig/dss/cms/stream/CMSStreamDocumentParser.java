package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.stream.bc.MessageDigestCalculatorProvider;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

/**
 * This class parses a document containing a CMS to a {@code eu.europa.esig.dss.cms.stream.CMSSignedDataStream} object
 * 
 */
public class CMSStreamDocumentParser {

    private static final Logger LOG = LoggerFactory.getLogger(CMSStreamDocumentParser.class);

    /**
     * Singleton
     */
    private CMSStreamDocumentParser() {
        // empty
    }

    /**
     * Parses {@code DSSDocument} and returns a {@code CMSSignedDataStream}
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link CMSSignedDataStream}
     */
    public static CMSSignedDataStream fromDSSDocument(DSSDocument document) {
        try (InputStream is = document.openStream();
             BufferedInputStream bis = new BufferedInputStream(is)) {
            CMSSignedDataParser cmsSignedDataParser = new CMSSignedDataParser(new MessageDigestCalculatorProvider(), bis);
            return parseCMSSignedDataStream(document, cmsSignedDataParser);

        } catch (CMSException | IOException e) {
            throw new DSSException(String.format("Unable to read a CMS. Reason : %s", e.getMessage()), e);
        }
    }
    /**
     * Parses {@code binaries} and returns a {@code CMSSignedDataStream}
     *
     * @param binaries {@link DSSDocument} to parse
     * @return {@link CMSSignedDataStream}
     */
    public static CMSSignedDataStream fromBinaries(byte[] binaries) {
        return fromDSSDocument(new InMemoryDocument(binaries));
    }

    @SuppressWarnings("unchecked")
    private static CMSSignedDataStream parseCMSSignedDataStream(DSSDocument document, CMSSignedDataParser cmsSignedDataParser) throws CMSException, IOException {
        /*
         * SignedData ::= SEQUENCE {
         *  version CMSVersion,
         *  digestAlgorithms DigestAlgorithmIdentifiers,
         *  encapContentInfo EncapsulatedContentInfo,
         *  certificates [0] IMPLICIT CertificateSet OPTIONAL,
         *  crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
         *  signerInfos SignerInfos }
         */

        CMSSignedDataStream cms = new CMSSignedDataStream();

        int version = cmsSignedDataParser.getVersion();
        cms.setVersion(version);

        Set<AlgorithmIdentifier> digestAlgorithmIDs = cmsSignedDataParser.getDigestAlgorithmIDs();
        cms.setDigestAlgorithmIDs(digestAlgorithmIDs);

        String signedContentTypeOID = cmsSignedDataParser.getSignedContentTypeOID();
        if (signedContentTypeOID != null) {
            cms.setSignedContentType(new ASN1ObjectIdentifier(signedContentTypeOID));
        }

        CMSTypedStream signedContent = cmsSignedDataParser.getSignedContent();
        boolean isDetachedSignature = isDetachedSignature(signedContent);
        cms.setDetachedSignature(isDetachedSignature);
        if (!isDetachedSignature) {
            cms.setSignedContent(readSignedContent(document, signedContent, cms.getSignedContentType(), digestAlgorithmIDs));
        }

        Store<X509CertificateHolder> certificates = (Store<X509CertificateHolder>) cmsSignedDataParser.getCertificates();
        cms.setCertificates(certificates);

        Store<X509CRLHolder> crls = (Store<X509CRLHolder>) cmsSignedDataParser.getCRLs();
        cms.setCRLs(crls);

        Store<X509AttributeCertificateHolder> attributeCertificates = cmsSignedDataParser.getAttributeCertificates();
        cms.setAttributeCertificates(attributeCertificates);

        Store<?> otherRevocationInfo = cmsSignedDataParser.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
        cms.setOcspResponseStore(otherRevocationInfo);

        otherRevocationInfo = cmsSignedDataParser.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
        cms.setOcspBasicStore(otherRevocationInfo);

        SignerInformationStore signerInfos = cmsSignedDataParser.getSignerInfos();
        cms.setSignerInfos(signerInfos);

        return cms;
    }

    private static boolean isDetachedSignature(CMSTypedStream signedContent) {
        return signedContent == null;
    }

    private static DSSDocument readSignedContent(DSSDocument document, CMSTypedStream signedContent,
                                                 ASN1ObjectIdentifier signedContentTypeOID,
                                                 Set<AlgorithmIdentifier> digestAlgorithmIDs) throws IOException {
        if (signedContent == null) {
            // detached signature
            return null;
        }

        try (InputStream is = signedContent.getContentStream()) {
            // we do not know what DigestAlgorithm has been used on signing, thus we compute digests for all
            CMSSignedContentDocument cmsWrappedDocument = new CMSSignedContentDocument(document);
            cmsWrappedDocument.setSignedContentType(signedContentTypeOID);

            Set<DigestAlgorithm> digestAlgorithms = getDigestAlgorithms(digestAlgorithmIDs);
            if (Utils.isCollectionNotEmpty(digestAlgorithms)) {
                DSSMessageDigestCalculator dssMessageDigestCalculator = new DSSMessageDigestCalculator(digestAlgorithms);
                dssMessageDigestCalculator.update(is);

                for (DigestAlgorithm digestAlgorithm : digestAlgorithms) {
                    DSSMessageDigest messageDigest = dssMessageDigestCalculator.getMessageDigest(digestAlgorithm);
                    cmsWrappedDocument.addDigest(messageDigest);
                }

            } else {
                LOG.warn("No supported digest algorithms found. Stream signed content into void.");
                is.readAllBytes();
            }
            return cmsWrappedDocument;
        }
    }

    private static Set<DigestAlgorithm> getDigestAlgorithms(Set<AlgorithmIdentifier> digestAlgorithmIDs) {
        Set<DigestAlgorithm> result = new HashSet<>();
        for (AlgorithmIdentifier algorithmIdentifier : digestAlgorithmIDs) {
            try {
                DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(algorithmIdentifier.getAlgorithm().getId());
                result.add(digestAlgorithm);
            } catch (Exception e) {
                LOG.warn("Unable to retrieve digest value for an algorithm '{}'. Reason : {}",
                        algorithmIdentifier.getAlgorithm().getId(), e.getMessage());
            }
        }
        return result;
    }
    
}
