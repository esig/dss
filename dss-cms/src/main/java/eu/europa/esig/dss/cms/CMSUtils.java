package eu.europa.esig.dss.cms;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Contains utils methods for CMS processing
 *
 */
public final class CMSUtils {

    /**
     * Default constructor
     */
    private CMSUtils() {
        // empty
    }

    /**
     * The provided implementation of CMS Utils
     */
    private static ICMSUtils impl;

    static {
        ServiceLoader<ICMSUtils> loader = ServiceLoader.load(ICMSUtils.class);
        Iterator<ICMSUtils> iterator = loader.iterator();
        if (!iterator.hasNext()) {
            throw new ExceptionInInitializerError(
                    "No implementation found for ICMSUtils in classpath, please choose between dss-cades-cms or dss-cades-cms-stream");
        }
        impl = iterator.next();
    }

    /**
     * Parses the given {@code DSSDocument} to a {@code CMS} object
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link CMS}
     */
    public static CMS parseToCMS(DSSDocument document) {
        return impl.parseToCMS(document);
    }

    /**
     * Parses the given byte array to a {@code CMS} object
     *
     * @param binaries byte array to parse
     * @return {@link CMS}
     */
    public static CMS parseToCMS(byte[] binaries) {
        return impl.parseToCMS(binaries);
    }

    /**
     * Creates a {@code DSSDocument} from the given {@code CMS}.
     * This method uses a {@code resourcesHandlerBuilder} which defines the final document's implementation
     * (e.g. in-memory document or a temporary document in a filesystem).
     *
     * @param cms {@link CMS} to create a document from
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return {@link DSSDocument}
     */
    public static DSSDocument writeToDSSDocument(CMS cms, DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
        return impl.writeToDSSDocument(cms, resourcesHandlerBuilder);
    }

    /**
     * This method re-created the {@code SignerInformation} with a given {@code signerId} from {@code CMS}
     * by providing the {@code digestCalculatorProvider} to the validation.
     * The returned {@code SignerInformation} contains validated digest according to the provided document.
     *
     * @param cms {@link CMS} containing a SignerInformation to be validated
     * @param signerId {@link SignerId} to re-compute
     * @param digestCalculatorProvider {@link DigestCalculatorProvider} containing digest of the original signed document
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return {@link SignerInformation}
     * @throws CMSException if an exception occurs on SignerInformation re-creation
     */
    public static SignerInformation recomputeSignerInformation(CMS cms, SignerId signerId, DigestCalculatorProvider digestCalculatorProvider,
                                                 DSSResourcesHandlerBuilder resourcesHandlerBuilder) throws CMSException {
        return impl.recomputeSignerInformation(cms, signerId, digestCalculatorProvider, resourcesHandlerBuilder);
    }

    /**
     * Replaces the signers within {@code cms} with the {@code newSignerStore}
     *
     * @param cms {@link CMS} to replace signers in
     * @param newSignerStore {@link SignerInformationStore} representing the new signers to be replaced with
     * @return {@link CMS} containing the new signers store
     */
    public static CMS replaceSigners(CMS cms, SignerInformationStore newSignerStore) {
        return impl.replaceSigners(cms, newSignerStore);
    }

    /**
     * Replaces SignedData content within the {@code CMS} with the provided values
     *
     * @param cms {@link CMS} to replace content in
     * @param certificates {@link Store}
     * @param attributeCertificates {@link Store}
     * @param crls {@link Store}
     * @param ocspResponsesStore {@link Store}
     * @param ocspBasicStore {@link Store}
     * @return {@link CMS}
     */
    public static CMS replaceCertificatesAndCRLs(CMS cms, Store<X509CertificateHolder> certificates,
                                                 Store<X509AttributeCertificateHolder> attributeCertificates,
                                                 Store<X509CRLHolder> crls, Store<?> ocspResponsesStore, Store<?> ocspBasicStore) {
        return impl.replaceCertificatesAndCRLs(cms, certificates, attributeCertificates, crls, ocspResponsesStore, ocspBasicStore);
    }

    /**
     * Adds digest algorithms to {@code CMSSignedData}
     *
     * @param cms {@link CMS} to extend
     * @param digestAlgorithmsToAdd a collection of digest {@link AlgorithmIdentifier}s to be included
     * @return {@link CMS}
     */
    public static CMS populateDigestAlgorithmSet(CMS cms, Collection<AlgorithmIdentifier> digestAlgorithmsToAdd) {
        return impl.populateDigestAlgorithmSet(cms, digestAlgorithmsToAdd);
    }

    /**
     * Converts a {@code TimeStampToken} to a {@code CMS}
     *
     * @param timeStampToken {@link TimeStampToken}
     * @return {@link CMS}
     */
    public static CMS toCMS(TimeStampToken timeStampToken) {
        return impl.toCMS(timeStampToken);
    }

    /**
     * Gets encoding of the ContentInfo of CMS
     *
     * @param cms {@link CMS} to check
     * @return {@link String} encoding, e.g. 'DER' or 'BER'
     */
    public static String getContentInfoEncoding(CMS cms) {
        return impl.getContentInfoEncoding(cms);
    }

    /**
     * Writes the encoded binaries of the SignedData.digestAlgorithms field to the given {@code OutputStream}
     * NOTE: This method is used for evidence record hash computation
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public static void writeSignedDataDigestAlgorithmsEncoded(CMS cms, OutputStream os) throws IOException {
        impl.writeSignedDataDigestAlgorithmsEncoded(cms, os);
    }

    /**
     * Writes the encoded binaries of the ContentInfo element to the given {@code OutputStream}
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public static void writeContentInfoEncoded(CMS cms, OutputStream os) throws IOException {
        impl.writeContentInfoEncoded(cms, os);
    }

    /**
     * Writes the encoded binaries of the SignedData.certificates field to the given {@code OutputStream}
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public static void writeSignedDataCertificatesEncoded(CMS cms, OutputStream os) throws IOException {
        impl.writeSignedDataCertificatesEncoded(cms, os);
    }

    /**
     * Writes the encoded binaries of the SignedData.crls field to the given {@code OutputStream}
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public static void writeSignedDataCRLsEncoded(CMS cms, OutputStream os) throws IOException {
        impl.writeSignedDataCRLsEncoded(cms, os);
    }

    /**
     * Writes the encoded binaries of the SignedData.signerInfos field to the given {@code OutputStream}
     * NOTE: This method is used for evidence record hash computation
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    public static void writeSignedDataSignerInfosEncoded(CMS cms, OutputStream os) throws IOException {
        impl.writeSignedDataSignerInfosEncoded(cms, os);
    }

    /**
     * Converts a {@code DSSDocument} to the corresponding {@code CMSTypedData} object type
     *
     * @param document {@link DSSDocument}
     * @return {@link CMSTypedData}
     */
    public static CMSTypedData toCMSEncapsulatedContent(DSSDocument document) {
        return impl.toCMSEncapsulatedContent(document);
    }

    /**
     * This method is used to verify whether the provided {@code DSSResourcesHandlerBuilder} is supported by
     * the current implementation. Returns the given value in case of success.
     *
     * @param dssResourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return {@link DSSResourcesHandlerBuilder}
     */
    public static DSSResourcesHandlerBuilder getDSSResourcesHandlerBuilder(DSSResourcesHandlerBuilder dssResourcesHandlerBuilder) {
        return impl.getDSSResourcesHandlerBuilder(dssResourcesHandlerBuilder);
    }

    /**
     * This method replaces {@code unsignedAttributes} within the given {@code signerInformation}
     *
     * @param signerInformation {@link SignerInformation} to replace unsigned attributes table into
     * @param unsignedAttributes {@link AttributeTable} containing the unsigned properties to be replaced with
     * @return {@link SignerInformation} updated
     */
    public static SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation, AttributeTable unsignedAttributes) {
        return impl.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
    }

    /**
     * This method returns whether the augmentation of signatures with an archive-time-stamp-v2 is supported by
     * the current implementation
     */
    public static void assertATSv2AugmentationSupported() {
        impl.assertATSv2AugmentationSupported();
    }

    /**
     * This method checks whether the embedding of existing Evidence Records within CMS
     * is supported by the current implementation
     */
    public static void assertEvidenceRecordEmbeddingSupported() {
        impl.assertEvidenceRecordEmbeddingSupported();
    }

}
