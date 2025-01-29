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

    int getVersion();

    Set<AlgorithmIdentifier> getDigestAlgorithmIDs();

    boolean isDetachedSignature();

    ASN1ObjectIdentifier getSignedContentType();

    DSSDocument getSignedContent();

    Store<X509CertificateHolder> getCertificates();

    Store<X509CRLHolder> getCRLs();

    Store<X509AttributeCertificateHolder> getAttributeCertificates();

    Store<?> getOcspResponseStore();

    Store<?> getOcspBasicStore();

    SignerInformationStore getSignerInfos();

    byte[] getEncoded();

}
