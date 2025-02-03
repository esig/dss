package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Implementation of a {@code CMS} based on a parsed content.
 *
 */
public class CMSSignedDataStream implements CMS {

    /** SignedData.version value */
    private int version;

    /** SignedData.digestAlgorithms value */
    private Set<AlgorithmIdentifier> digestAlgorithmIDs;

    /** Whether the signature is detached */
    private boolean isDetachedSignature;

    /** SignedData.encapContentInfo.eContentType value */
    private ASN1ObjectIdentifier signedContentType = PKCSObjectIdentifiers.data;

    /** SignedData.encapContentInfo.eContent value */
    private DSSDocument signedContent;

    /** SignedData.certificates value */
    private Store<X509CertificateHolder> certificates;

    /** Attribute certificates store */
    private Store<X509AttributeCertificateHolder> attributeCertificates;

    /** SignedData.crls value */
    private Store<X509CRLHolder> crls;

    /** OCSP responses store */
    private Store<?> ocspResponseStore;

    /** OCSP basic store */
    private Store<?> ocspBasicStore;

    /** SignedData.signerInfos value */
    private SignerInformationStore signerInfos;

    /**
     * Default constructor
     */
    public CMSSignedDataStream() {
        // empty
    }

    @Override
    public int getVersion() {
        return version;
    }

    /**
     * Sets value of SignedData.version field
     *
     * @param version integer value
     */
    public void setVersion(int version) {
        this.version = version;
    }

    @Override
    public Set<AlgorithmIdentifier> getDigestAlgorithmIDs() {
        return digestAlgorithmIDs;
    }

    /**
     * Sets a set of algorithm identifiers (OIDs) incorporated within SignedData.digestAlgorithms field of CMS
     *
     * @param digestAlgorithmIDs a collection of {@link AlgorithmIdentifier}s
     */
    public void setDigestAlgorithmIDs(Collection<AlgorithmIdentifier> digestAlgorithmIDs) {
        this.digestAlgorithmIDs = new LinkedHashSet<>(digestAlgorithmIDs);
    }

    @Override
    public boolean isDetachedSignature() {
        return isDetachedSignature;
    }

    /**
     * Sets whether the signature is detached (i.e. SignedData.encapContentInfo.eContent is null)
     *
     * @param detachedSignature whether the signature is detached
     */
    public void setDetachedSignature(boolean detachedSignature) {
        isDetachedSignature = detachedSignature;
    }

    @Override
    public ASN1ObjectIdentifier getSignedContentType() {
        return signedContentType;
    }

    /**
     * Sets signed content type, present within the SignedData.encapContentInfo.eContentType field
     *
     * @param signedContentType {@link ASN1ObjectIdentifier}
     */
    public void setSignedContentType(ASN1ObjectIdentifier signedContentType) {
        this.signedContentType = signedContentType;
    }

    @Override
    public DSSDocument getSignedContent() {
        return signedContent;
    }

    /**
     * Sets the signed content incorporated within the SignedData.encapContentInfo.eContent field
     *
     * @param signedContent {@link DSSDocument}
     */
    public void setSignedContent(DSSDocument signedContent) {
        this.signedContent = signedContent;
    }

    @Override
    public Store<X509CertificateHolder> getCertificates() {
        return certificates;
    }

    /**
     * Sets the certificates store, representing the value of SignedData.certificates field
     *
     * @param certificates {@link Store}
     */
    public void setCertificates(Store<X509CertificateHolder> certificates) {
        this.certificates = certificates;
    }

    @Override
    public Store<X509AttributeCertificateHolder> getAttributeCertificates() {
        return attributeCertificates;
    }

    /**
     * Sets attribute certificates incorporates within CMS
     *
     * @param attributeCertificates {@link Store}
     */
    public void setAttributeCertificates(Store<X509AttributeCertificateHolder> attributeCertificates) {
        this.attributeCertificates = attributeCertificates;
    }

    @Override
    public Store<X509CRLHolder> getCRLs() {
        if (crls == null) {
            return new CollectionStore<>(new ArrayList<>());
        }
        return crls;
    }

    /**
     * Sets the CRLs store (OCSP excluded), representing the value of SignedData.crls field
     *
     * @param crls {@link Store}
     */
    public void setCRLs(Store<X509CRLHolder> crls) {
        this.crls = crls;
    }

    @Override
    public Store<?> getOcspResponseStore() {
        if (ocspResponseStore == null) {
            return new CollectionStore<>(new ArrayList<>());
        }
        return ocspResponseStore;
    }

    /**
     * Sets the OCSP Responses Store, incorporated within the SignedData.crls field
     *
     * @param ocspResponseStore {@link Store}
     */
    public void setOcspResponseStore(Store<?> ocspResponseStore) {
        this.ocspResponseStore = ocspResponseStore;
    }

    @Override
    public Store<?> getOcspBasicStore() {
        if (ocspBasicStore == null) {
            return new CollectionStore<>(new ArrayList<>());
        }
        return ocspBasicStore;
    }

    /**
     * Sets the OCSP Basic Store, incorporated within the SignedData.crls field
     *
     * @param ocspBasicStore {@link Store}
     */
    public void setOcspBasicStore(Store<?> ocspBasicStore) {
        this.ocspBasicStore = ocspBasicStore;
    }

    @Override
    public SignerInformationStore getSignerInfos() {
        return signerInfos;
    }

    /**
     * Sets the signers of the signature, incorporated within the SignedData.signerInfos field
     *
     * @param signerInfos {@link SignerInformationStore}
     */
    public void setSignerInfos(SignerInformationStore signerInfos) {
        this.signerInfos = signerInfos;
    }

    @Override
    public byte[] getDEREncoded() {
        /*
         * Due to a limitation of CMSSignedDataStreamGenerator (see {@link https://github.com/bcgit/bc-java/issues/1482})
         * we are not able to generate a DER-encoded content using streaming.
         * Therefore, we need to post-process the output and DER-encode the data.
         * NOTE: This method should not be used on an enveloping CMS signature creation,
         * but only for detached CMS (such as PDF signature, timestamp token, etc.).
         */
        final CMSStreamDocumentBuilder cmsStreamDocumentBuilder = new CMSStreamDocumentBuilder();
        CMSSignedDataStreamGenerator generator = cmsStreamDocumentBuilder.createCMSSignedDataStreamGenerator(this);
        CMSProcessable content = cmsStreamDocumentBuilder.getContentToBeSigned(this);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            try (OutputStream gos = generator.open(getSignedContentType(), baos, !isDetachedSignature())) {
                content.write(gos);
            }
            byte[] cmsSignedData = baos.toByteArray();
            return DSSASN1Utils.getDEREncoded(cmsSignedData);

        } catch (CMSException | IOException e) {
            throw new DSSException("Unable to return CMS encoded", e);
        }
    }

}
