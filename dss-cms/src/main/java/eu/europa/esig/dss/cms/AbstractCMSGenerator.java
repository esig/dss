package eu.europa.esig.dss.cms;

import eu.europa.esig.dss.model.DSSDocument;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import java.util.Collection;

/**
 * Abstract implementation of the {@code CMSGenerator} containing the set variable values
 *
 */
public abstract class AbstractCMSGenerator implements CMSGenerator {

    /** New signer to be generated */
    protected SignerInfoGenerator signerInfoGenerator;

    /** Collection of certificates to be encapsulated within SignedData.certificates field */
    protected Store<X509CertificateHolder> certificateStore;

    /** Collection of existing signers to be added */
    protected SignerInformationStore signers;

    /** Collection of attribute certificates */
    protected Store<X509AttributeCertificateHolder> attributeCertificates;

    /** Collection of CRLs to be encapsulated within SignedData.crls field */
    protected Store<X509CRLHolder> crls;

    /** Collection of OCSP basic responses */
    protected Store<?> ocspBasicStore;

    /** Collection of OCSP responses */
    protected Store<?> ocspResponsesStore;

    /** Collection of digest algorithms to be included */
    protected Collection<AlgorithmIdentifier> digestAlgorithmIDs;

    /** The document to be signed */
    protected DSSDocument toBeSignedDocument;

    /** Whether the signed document shall be encapsulated within the CMS */
    protected boolean encapsulate;

    /**
     * Default constructor
     */
    protected AbstractCMSGenerator() {
        // empty
    }

    @Override
    public void setSignerInfoGenerator(SignerInfoGenerator signerInfoGenerator) {
        this.signerInfoGenerator = signerInfoGenerator;
    }

    @Override
    public void setCertificates(Store<X509CertificateHolder> certificateStore) {
        this.certificateStore = certificateStore;
    }

    @Override
    public void setSigners(SignerInformationStore signers) {
        this.signers = signers;
    }

    @Override
    public void setAttributeCertificates(Store<X509AttributeCertificateHolder> attributeCertificates) {
        this.attributeCertificates = attributeCertificates;
    }

    @Override
    public void setCRLs(Store<X509CRLHolder> crls) {
        this.crls = crls;
    }

    @Override
    public void setOcspBasicStore(Store<?> ocspBasicStore) {
        this.ocspBasicStore = ocspBasicStore;
    }

    @Override
    public void setOcspResponsesStore(Store<?> ocspResponsesStore) {
        this.ocspResponsesStore = ocspResponsesStore;
    }

    @Override
    public void setDigestAlgorithmIDs(Collection<AlgorithmIdentifier> digestAlgorithmIDs) {
        this.digestAlgorithmIDs = digestAlgorithmIDs;
    }

    @Override
    public void setToBeSignedDocument(DSSDocument toBeSignedDocument) {
        this.toBeSignedDocument = toBeSignedDocument;
    }

    @Override
    public void setEncapsulate(boolean encapsulate) {
        this.encapsulate = encapsulate;
    }

}
