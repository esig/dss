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
     * Creates a {@code DSSDocument} from the given {@code CMS} using the implementation based coding.
     * This method uses a {@code resourcesHandlerBuilder} which defines the final document's implementation
     * (e.g. in-memory document or a temporary document in a filesystem).
     * NOTE: When used, the dss-cms-object implementation stores document using a DL coding,
     *       and dss-cms-stream stores documents using BER coding.
     *
     * @param cms {@link CMS} to create a document from
     * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
     * @return {@link DSSDocument}
     */
    DSSDocument writeToDSSDocument(CMS cms, DSSResourcesHandlerBuilder resourcesHandlerBuilder);

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
    SignerInformation recomputeSignerInformation(CMS cms, SignerId signerId, DigestCalculatorProvider digestCalculatorProvider,
                                                 DSSResourcesHandlerBuilder resourcesHandlerBuilder) throws CMSException;

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
     * Gets encoding of the ContentInfo of CMS
     *
     * @param cms {@link CMS} to check
     * @return {@link String} encoding, e.g. 'DER' or 'BER'
     */
    String getContentInfoEncoding(CMS cms);

    /**
     * Writes the encoded binaries of the SignedData.digestAlgorithms field to the given {@code OutputStream}
     * NOTE: This method is used for evidence record hash computation
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    void writeSignedDataDigestAlgorithmsEncoded(CMS cms, OutputStream os) throws IOException;

    /**
     * Writes the encoded binaries of the ContentInfo element to the given {@code OutputStream}
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    void writeContentInfoEncoded(CMS cms, OutputStream os) throws IOException;

    /**
     * Writes the encoded binaries of the SignedData.certificates field to the given {@code OutputStream}
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    void writeSignedDataCertificatesEncoded(CMS cms, OutputStream os) throws IOException;

    /**
     * Writes the encoded binaries of the SignedData.crls field to the given {@code OutputStream}
     * NOTE: This method is used for archive-time-stamp-v2 message-imprint computation.
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    void writeSignedDataCRLsEncoded(CMS cms, OutputStream os) throws IOException;

    /**
     * Writes the encoded binaries of the SignedData.signerInfos field to the given {@code OutputStream}
     * NOTE: This method is used for evidence record hash computation
     *
     * @param cms {@link CMS}
     * @param os {@link OutputStream}
     * @throws IOException if an exception occurs on bytes writing
     */
    void writeSignedDataSignerInfosEncoded(CMS cms, OutputStream os) throws IOException;

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

    /**
     * This method checks whether the augmentation of signatures with an archive-time-stamp-v2 is supported by
     * the current implementation
     */
    void assertATSv2AugmentationSupported();

    /**
     * This method checks whether the embedding of existing Evidence Records within CMS
     * is supported by the current implementation
     */
    void assertEvidenceRecordEmbeddingSupported();

}
