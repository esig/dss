package eu.europa.esig.dss.cms;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.util.Collection;

/**
 * The interface of Utils class for processing {@code CMS}
 *
 */
public interface ICMSUtils {

    /**
     * Parses the given {@code DSSDocument} to a {@code CMS} object
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link CMS}
     */
    CMS parseToCMS(DSSDocument document);

    /**
     * Parses the given byte array to a {@code CMS} object
     *
     * @param binaries byte array to parse
     * @return {@link CMS}
     */
    CMS parseToCMS(byte[] binaries);

    /**
     * Creates a {@code DSSDocument} from the given {@code CMS}
     * This method uses a {@code resourcesHandlerBuilder} which defines the final document's implementation
     * (e.g. in-memory document or a temporary document in a filesystem).
     *
     * @param cms {@link CMS} to create a document from
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return {@link DSSDocument}
     */
    DSSDocument writeToDSSDocument(CMS cms, DSSResourcesHandlerBuilder resourcesHandlerBuilder);

    /**
     * Replaces the signers within {@code cms} with the {@code newSignerStore}
     *
     * @param cms {@link CMS} to replace signers in
     * @param newSignerStore {@link SignerInformationStore} representing the new signers to be replaced with
     * @return {@link CMS} containing the new signers store
     */
    CMS replaceSigners(CMS cms, SignerInformationStore newSignerStore);

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
    CMS replaceCertificatesAndCRLs(CMS cms, Store<X509CertificateHolder> certificates,
                                   Store<X509AttributeCertificateHolder> attributeCertificates,
                                   Store<X509CRLHolder> crls, Store<?> ocspResponsesStore, Store<?> ocspBasicStore);

    /**
     * Adds digest algorithms to {@code CMSSignedData}
     *
     * @param cms {@link CMS} to extend
     * @param digestAlgorithmsToAdd a collection of digest {@link AlgorithmIdentifier}s to be included
     * @return {@link CMS}
     */
    CMS populateDigestAlgorithmSet(CMS cms, Collection<AlgorithmIdentifier> digestAlgorithmsToAdd);

    /**
     * Converts a {@code TimeStampToken} to a {@code CMS}
     *
     * @param timeStampToken {@link TimeStampToken}
     * @return {@link CMS}
     */
    CMS toCMS(TimeStampToken timeStampToken);

    /**
     * Gets the encoded binaries of the ContentInfo element.
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @return binaries
     */
    byte[] getContentInfoEncoded(CMS cms);

    /**
     * Gets the encoded binaries of the SignedData.certificates field.
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @return binaries
     */
    byte[] getSignedDataCertificatesEncoded(CMS cms);

    /**
     * Gets the encoded binaries of the SignedData.crls field.
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @return binaries
     */
    byte[] getSignedDataCRLsEncoded(CMS cms);

    /**
     * Converts a {@code DSSDocument} to the corresponding {@code CMSTypedData} object type
     *
     * @param document {@link DSSDocument}
     * @return {@link CMSTypedData}
     */
    CMSTypedData toCMSEncapsulatedContent(DSSDocument document);

    /**
     * This method is used to verify whether the provided {@code DSSResourcesHandlerBuilder} is supported by
     * the current implementation. Returns the given value in case of success.
     *
     * @param dssResourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return {@link DSSResourcesHandlerBuilder}
     */
    DSSResourcesHandlerBuilder getDSSResourcesHandlerBuilder(DSSResourcesHandlerBuilder dssResourcesHandlerBuilder);

    /**
     * This method replaces {@code unsignedAttributes} within the given {@code signerInformation}
     *
     * @param signerInformation {@link SignerInformation} to replace unsigned attributes table into
     * @param unsignedAttributes {@link AttributeTable} containing the unsigned properties to be replaced with
     * @return {@link SignerInformation} updated
     */
    SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation, AttributeTable unsignedAttributes);

}
