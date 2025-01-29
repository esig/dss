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
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Generates a {@code eu.europa.esig.dss.eu.europa.esig.dss.cms.CMS} with the given input data
 *
 */
public interface CMSGenerator {

    /**
     * Adds a SignerInfoGenerator containing information about a new signer to be embedded within CMS
     *
     * @param signerInfoGenerator {@link SignerInfoGenerator}
     */
    void setSignerInfoGenerator(SignerInfoGenerator signerInfoGenerator);

    /**
     * Adds certificates to be embedded within SignedData.certificates field
     *
     * @param certificateStore {@link Store}
     */
    void setCertificates(Store<X509CertificateHolder> certificateStore);

    /**
     * Adds existing SignerInformation's
     *
     * @param signers {@link SignerInformationStore}
     */
    void setSigners(SignerInformationStore signers);

    /**
     * Adds attribute certificates
     *
     * @param attributeCertificates {@link Store}
     */
    void setAttributeCertificates(Store<X509AttributeCertificateHolder> attributeCertificates);

    /**
     * Adds CRLs
     *
     * @param crls {@link Store}
     */
    void setCRLs(Store<X509CRLHolder> crls);

    /**
     * Adds a collection of OCSP basic responses
     *
     * @param ocspBasicStore {@link Store}
     */
    void setOcspBasicStore(Store<?> ocspBasicStore);

    /**
     * Adds a collection of OCSP responses
     *
     * @param ocspResponsesStore {@link Store}
     */
    void setOcspResponsesStore(Store<?> ocspResponsesStore);

    /**
     * Adds a collection of digest algorithm IDs
     *
     * @param digestAlgorithmIDs a collection of {@code AlgorithmIdentifier}s
     */
    void setDigestAlgorithmIDs(Collection<AlgorithmIdentifier> digestAlgorithmIDs);

    /**
     * Adds a document to be signed
     *
     * @param document {@link DSSDocument}
     */
    void setToBeSignedDocument(DSSDocument document);

    /**
     * Sets whether the document shall be encapsulated within CMS
     *
     * @param encapsulate whether encapsulate the signed data
     */
    void setEncapsulate(boolean encapsulate);

    /**
     * Generates the {@code CMS}
     *
     * @return {@link CMS}
     */
    CMS generate();

    /**
     * Replaces content of {@code originalCMS} with certificate and CRL values specified within the CMSGenerator
     *
     * @param originalCMS {@link CMS} to be extended
     * @return {@link CMS} with the extended fields
     */
    CMS replaceCertificatesAndCRLs(CMS originalCMS);

    /**
     * Loads the available {@code CMSGenerator} based on the loaded module in the classpath.
     * One of the 'dss-cades-cms' or 'dss-cades-cms-stream' shall be defined in the list of dependencies.
     *
     * @return {@link CMSGenerator} implementation
     */
    static CMSGenerator loadCMSGenerator() {
        ServiceLoader<CMSGenerator> loader = ServiceLoader.load(CMSGenerator.class);
        Iterator<CMSGenerator> iterator = loader.iterator();
        if (!iterator.hasNext()) {
            throw new ExceptionInInitializerError(
                    "No implementation found for CMSGenerator in the classpath, please choose between 'dss-cms-object' or 'dss-cms-stream'!");
        }
        return iterator.next();
    }

}
