package eu.europa.esig.dss.cms;

import eu.europa.esig.dss.model.DSSDocument;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import java.util.Set;

/**
 * Represents a content of a CMS Signed Data object
 *
 */
public interface CMS {

    /**
     * Returns value of SignedData.version field
     *
     * @return integer value
     */
    int getVersion();

    /**
     * Returns a set of algorithm identifiers (OIDs) incorporated within SignedData.digestAlgorithms field of CMS
     *
     * @return a set of {@link AlgorithmIdentifier}s
     */
    Set<AlgorithmIdentifier> getDigestAlgorithmIDs();

    /**
     * Returns whether the signature is detached (i.e. SignedData.encapContentInfo.eContent is null)
     *
     * @return whether the signature is detached
     */
    boolean isDetachedSignature();

    /**
     * Gets signed content type, present within the SignedData.encapContentInfo.eContentType field
     *
     * @return {@link ASN1ObjectIdentifier}
     */
    ASN1ObjectIdentifier getSignedContentType();

    /**
     * Gets the signed content incorporated within the SignedData.encapContentInfo.eContent field
     *
     * @return {@link DSSDocument}
     */
    DSSDocument getSignedContent();

    /**
     * Gets the certificates store, representing the value of SignedData.certificates field
     *
     * @return {@link Store}
     */
    Store<X509CertificateHolder> getCertificates();

    /**
     * Gets attribute certificates incorporates within CMS
     *
     * @return {@link Store}
     */
    Store<X509AttributeCertificateHolder> getAttributeCertificates();

    /**
     * Gets the CRLs store (OCSP excluded), representing the value of SignedData.crls field
     *
     * @return {@link Store}
     */
    Store<X509CRLHolder> getCRLs();

    /**
     * Gets the OCSP Responses Store, incorporated within the SignedData.crls field
     *
     * @return {@link Store}
     */
    Store<?> getOcspResponseStore();

    /**
     * Gets the OCSP Basic Store, incorporated within the SignedData.crls field
     *
     * @return {@link Store}
     */
    Store<?> getOcspBasicStore();

    /**
     * Gets the signers of the signature, incorporated within the SignedData.signerInfos field
     *
     * @return {@link SignerInformationStore}
     */
    SignerInformationStore getSignerInfos();

    /**
     * Gets DER-encoded content of the CMS SignedData.
     * NOTE: This method returns the encoded value using in-memory byte array. Not applicable for large CMS processing.
     *
     * @return DER-encoded binaries
     */
    byte[] getEncoded();

}
