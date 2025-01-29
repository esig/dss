package eu.europa.esig.dss.cms.object;

import eu.europa.esig.dss.cms.CMSSignedDocument;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.ICMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

/**
 * Implements {@code ICMSUtils} using a {@code eu.europa.esig.dss.cms.bc.CMSSignedDataWrapper} processing
 *
 */
public class CMSSignedDataUtils implements ICMSUtils {

    @Override
    public CMS parseToCMS(DSSDocument document) {
        if (document instanceof CMSSignedDocument) {
            return new CMSSignedDataObject(((CMSSignedDocument) document).getCMSSignedData());
        }
        return parseToCMS(document.openStream());
    }

    @Override
    public CMS parseToCMS(InputStream inputStream) {
        try (InputStream is = inputStream) {
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
    public DSSDocument writeToDSSDocument(CMS cms) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataBC(cms);
        return new CMSSignedDocument(cmsSignedDataObject.getCMSSignedData());
    }

    @Override
    public CMS replaceSigners(CMS cms, SignerInformationStore newSignerStore) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataBC(cms);
        CMSSignedData cmsSignedData = CMSSignedData.replaceSigners(cmsSignedDataObject.getCMSSignedData(), newSignerStore);
        return new CMSSignedDataObject(cmsSignedData);
    }

    @Override
    public CMS replaceCertificatesAndCRLs(CMS cms, Store<X509CertificateHolder> certificates, Store<X509AttributeCertificateHolder> attributeCertificates, Store<?> crls) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataBC(cms);
        try {
            CMSSignedData cmsSignedData = CMSSignedData.replaceCertificatesAndCRLs(cmsSignedDataObject.getCMSSignedData(), certificates, attributeCertificates, crls);
            return new CMSSignedDataObject(cmsSignedData);
        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to replace content of CMS SignedData. Reason : %s", e.getMessage()), e);
        }
    }

    @Override
    public CMS populateDigestAlgorithmSet(CMS cms, Collection<AlgorithmIdentifier> digestAlgorithmsToAdd) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataBC(cms);
        CMSSignedData cmsSignedData = cmsSignedDataObject.getCMSSignedData();
        for (AlgorithmIdentifier asn1ObjectIdentifier : digestAlgorithmsToAdd) {
            if (!cmsSignedData.getDigestAlgorithmIDs().contains(asn1ObjectIdentifier)) {
                cmsSignedData = CMSSignedData.addDigestAlgorithm(cmsSignedData, asn1ObjectIdentifier);
            }
        }
        return new CMSSignedDataObject(cmsSignedData);
    }

    private static CMSSignedDataObject toCMSSignedDataBC(CMS cms) {
        if (cms instanceof CMSSignedDataObject) {
            return (CMSSignedDataObject) cms;
        }
        throw new IllegalStateException("Only CMSSignedDataBC implementation is supported in 'dss-cades-cms' module!");
    }

    @Override
    public CMS toCMS(TimeStampToken timeStampToken) {
        return new CMSSignedDataObject(timeStampToken.toCMSSignedData());
    }

    @Override
    public byte[] getContentInfoEncoded(CMS cms) {
        SignedData signedData = getSignedData(cms);

        final ContentInfo content = signedData.getEncapContentInfo();
        byte[] contentInfoBytes;
        if (content.getContent() instanceof BEROctetString) {
            contentInfoBytes = DSSASN1Utils.getBEREncoded(content);
        } else {
            contentInfoBytes = DSSASN1Utils.getDEREncoded(content);
        }
        return contentInfoBytes;
    }

    @Override
    public byte[] getSignedDataCertificatesEncoded(CMS cms) {
        SignedData signedData = getSignedData(cms);

        byte[] certificatesBytes = null;

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
        }

        return certificatesBytes;
    }

    @Override
    public byte[] getSignedDataCRLsEncoded(CMS cms) {
        SignedData signedData = getSignedData(cms);

        byte[] crlBytes = null;

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
        }
        return crlBytes;
    }

    private SignedData getSignedData(CMS cms) {
        CMSSignedDataObject cmsSignedDataObject = toCMSSignedDataBC(cms);
        final ContentInfo contentInfo = cmsSignedDataObject.getCMSSignedData().toASN1Structure();
        return SignedData.getInstance(contentInfo.getContent());
    }

}
