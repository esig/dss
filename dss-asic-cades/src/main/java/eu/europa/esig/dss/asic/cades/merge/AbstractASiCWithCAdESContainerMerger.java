package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.merge.DefaultContainerMerger;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

/**
 * This class contains common code for ASiC with CAdES container merger classes.
 *
 */
public abstract class AbstractASiCWithCAdESContainerMerger extends DefaultContainerMerger {

    /**
     * Empty constructor
     */
    AbstractASiCWithCAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC With CAdES container merger from provided container documents
     *
     * @param containerOne {@link DSSDocument} first container to be merged
     * @param containerTwo {@link DSSDocument} second container to be merged
     */
    protected AbstractASiCWithCAdESContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        super(containerOne, containerTwo);
    }

    /**
     * This constructor is used to create an ASiC With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} first ASiC Content to be merged
     * @param asicContentTwo {@link ASiCContent} second ASiC Content to be merged
     */
    protected AbstractASiCWithCAdESContainerMerger(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        super(asicContentOne, asicContentTwo);
    }

    @Override
    public boolean isSupported(DSSDocument container) {
        return new ASiCContainerWithCAdESValidatorFactory().isSupported(container);
    }

    @Override
    public boolean isSupported(ASiCContent asicContent) {
        return new ASiCContainerWithCAdESValidatorFactory().isSupported(asicContent);
    }

    @Override
    protected AbstractASiCContainerExtractor getContainerExtractor(DSSDocument container) {
        return new ASiCWithCAdESContainerExtractor(container);
    }

    /**
     * This method merges two signature documents representing CMS signatures into one CMS signature document.
     *
     * @param signatureDocumentOne {@link DSSDocument}
     * @param signatureDocumentTwo {@link DSSDocument}
     * @return merged CMS {@link DSSDocument}
     */
    protected DSSDocument mergeCmsSignatures(DSSDocument signatureDocumentOne, DSSDocument signatureDocumentTwo) {
        CMSDocumentValidator documentValidatorOne = new CMSDocumentValidator(signatureDocumentOne);
        CMSDocumentValidator documentValidatorTwo = new CMSDocumentValidator(signatureDocumentTwo);

        try {

            CMSSignedData cmsSignedDataOne = documentValidatorOne.getCmsSignedData();
            CMSSignedData cmsSignedDataTwo = documentValidatorTwo.getCmsSignedData();

            SignerInformationStore signerInformationStore = getSignerInformationStore(cmsSignedDataOne, cmsSignedDataTwo);
            CMSSignedData mergedCmsSignedData = CMSSignedData.replaceSigners(cmsSignedDataOne, signerInformationStore);

            JcaCertStore certificatesStore = getCertificatesStore(cmsSignedDataOne, cmsSignedDataTwo);
            Store<Encodable> certAttributeStore = getCertAttributeStore(cmsSignedDataOne, cmsSignedDataTwo);
            Store<Encodable> crlStore = getCRLStore(cmsSignedDataOne, cmsSignedDataTwo);

            mergedCmsSignedData = CMSSignedData.replaceCertificatesAndCRLs(mergedCmsSignedData, certificatesStore, certAttributeStore, crlStore);
            mergedCmsSignedData = CMSUtils.populateDigestAlgorithmSet(mergedCmsSignedData, cmsSignedDataTwo);

            return new CMSSignedDocument(mergedCmsSignedData, signatureDocumentOne.getName());

        } catch (CMSException | CertificateEncodingException e) {
            throw new DSSException(String.format("Unable to merge ASiC-S with CAdES container. Reason : %s", e.getMessage()));
        }
    }

    private SignerInformationStore getSignerInformationStore(CMSSignedData... cmsSignedData) {
        List<SignerInformation> signerInformations = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedData) {
            signerInformations.addAll(signedData.getSignerInfos().getSigners());
        }
        return new SignerInformationStore(signerInformations);
    }

    private JcaCertStore getCertificatesStore(CMSSignedData... cmsSignedData) throws CertificateEncodingException {
        List<X509CertificateHolder> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedData) {
            final Collection<X509CertificateHolder> certificateHolders = signedData.getCertificates().getMatches(null);
            for (final X509CertificateHolder x509CertificateHolder : certificateHolders) {
                if (!result.contains(x509CertificateHolder)) {
                    result.add(x509CertificateHolder);
                }
            }
        }
        return new JcaCertStore(result);
    }

    private Store<Encodable> getCertAttributeStore(CMSSignedData... cmsSignedData) {
        List<Encodable> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedData) {
            final Collection<X509AttributeCertificateHolder> attributeCertificateHolders = signedData.getAttributeCertificates().getMatches(null);
            for (final X509AttributeCertificateHolder x509AttributeCertificateHolder : attributeCertificateHolders) {
                if (!result.contains(x509AttributeCertificateHolder)) {
                    result.add(x509AttributeCertificateHolder);
                }
            }
        }
        return new CollectionStore<>(result);
    }

    @SuppressWarnings("unchecked")
    private Store<Encodable> getCRLStore(CMSSignedData... cmsSignedData) {
        List<Encodable> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedData) {
            final Collection<X509CRLHolder> crlHolders = signedData.getCRLs().getMatches(null);
            for (final X509CRLHolder x509CRLHolder : crlHolders) {
                if (!result.contains(x509CRLHolder)) {
                    result.add(x509CRLHolder);
                }
            }
            final Collection<ASN1Encodable> basicOcsps = signedData.getOtherRevocationInfo(id_pkix_ocsp_basic).getMatches(null);
            for (final ASN1Encodable ocsp : basicOcsps) {
                OtherRevocationInfoFormat otherRevocationInfo = new OtherRevocationInfoFormat(id_pkix_ocsp_basic, ocsp);
                if (!result.contains(otherRevocationInfo)) {
                    result.add(otherRevocationInfo);
                }
            }
            final Collection<ASN1Encodable> ocspResponses = signedData.getOtherRevocationInfo(id_ri_ocsp_response).getMatches(null);
            for (final ASN1Encodable ocsp : ocspResponses) {
                OtherRevocationInfoFormat otherRevocationInfo = new OtherRevocationInfoFormat(id_ri_ocsp_response, ocsp);
                if (!result.contains(otherRevocationInfo)) {
                    result.add(otherRevocationInfo);
                }
            }
        }
        return new CollectionStore<>(result);
    }

}
