/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.merge.DefaultContainerMerger;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
import java.util.Objects;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

/**
 * This class contains common code for ASiC with CAdES container merger classes.
 *
 */
public abstract class AbstractASiCWithCAdESContainerMerger extends DefaultContainerMerger {

    /**
     * Defines rules for filename creation for new ZIP entries (e.g. signature files, etc.)
     */
    protected ASiCWithCAdESFilenameFactory asicFilenameFactory = new DefaultASiCWithCAdESFilenameFactory();

    /**
     * Empty constructor
     */
    AbstractASiCWithCAdESContainerMerger() {
        // empty
    }

    /**
     * This constructor is used to create an ASiC With CAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument} containers to be merged
     */
    protected AbstractASiCWithCAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    protected AbstractASiCWithCAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    /**
     * Sets {@code ASiCWithCAdESFilenameFactory} defining a set of rules for naming of newly create ZIP entries,
     * such as signature files.
     *
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    public void setAsicFilenameFactory(ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        Objects.requireNonNull(asicFilenameFactory, "ASiCWithCAdESFilenameFactory cannot be null!");
        this.asicFilenameFactory = asicFilenameFactory;
    }

    @Override
    protected boolean isSupported(DSSDocument container) {
        return new ASiCContainerWithCAdESValidatorFactory().isSupported(container);
    }

    @Override
    protected boolean isSupported(ASiCContent asicContent) {
        return new ASiCContainerWithCAdESValidatorFactory().isSupported(asicContent);
    }

    @Override
    protected DefaultASiCContainerExtractor getContainerExtractor(DSSDocument container) {
        return new ASiCWithCAdESContainerExtractor(container);
    }

    /**
     * This method merges signature documents representing CMS signatures into single CMS signature document.
     *
     * @param signatureDocuments a list of {@link DSSDocument}s representing CMS signatures to be merged
     * @return merged CMS {@link DSSDocument}
     */
    protected DSSDocument mergeCmsSignatures(List<DSSDocument> signatureDocuments) {
        try {
            List<CMSSignedData> cmsSignedDataList = getCMSSignedDataList(signatureDocuments);

            CMSSignedData originalCMSSignedData = cmsSignedDataList.iterator().next(); // getFirstCMSSignedData

            SignerInformationStore signerInformationStore = getSignerInformationStore(cmsSignedDataList);
            CMSSignedData mergedCmsSignedData = CMSSignedData.replaceSigners(originalCMSSignedData, signerInformationStore);

            JcaCertStore certificatesStore = getCertificatesStore(cmsSignedDataList);
            Store<Encodable> certAttributeStore = getCertAttributeStore(cmsSignedDataList);
            Store<Encodable> crlStore = getCRLStore(cmsSignedDataList);
            mergedCmsSignedData = CMSSignedData.replaceCertificatesAndCRLs(mergedCmsSignedData, certificatesStore, certAttributeStore, crlStore);

            List<AlgorithmIdentifier> digestAlgorithms = getDigestAlgorithms(cmsSignedDataList);
            for (AlgorithmIdentifier algorithmIdentifier : digestAlgorithms) {
                mergedCmsSignedData = CMSUtils.addDigestAlgorithm(mergedCmsSignedData, algorithmIdentifier);
            }

            return new CMSSignedDocument(mergedCmsSignedData, getSignatureDocumentName(signatureDocuments));

        } catch (CMSException | CertificateEncodingException e) {
            throw new DSSException(String.format("Unable to merge ASiC-S with CAdES container. Reason : %s", e.getMessage()));
        }
    }

    private List<CMSSignedData> getCMSSignedDataList(List<DSSDocument> signatureDocuments) {
        List<CMSSignedData> signedDataList = new ArrayList<>();
        for (DSSDocument signatureDocument : signatureDocuments) {
            CMSDocumentValidator documentValidator = new CMSDocumentValidator(signatureDocument);
            signedDataList.add(documentValidator.getCmsSignedData());
        }
        return signedDataList;
    }

    private SignerInformationStore getSignerInformationStore(List<CMSSignedData> cmsSignedDataList) {
        List<SignerInformation> signerInformations = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedDataList) {
            signerInformations.addAll(signedData.getSignerInfos().getSigners());
        }
        return new SignerInformationStore(signerInformations);
    }

    private JcaCertStore getCertificatesStore(List<CMSSignedData> cmsSignedDataList) throws CertificateEncodingException {
        List<X509CertificateHolder> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedDataList) {
            final Collection<X509CertificateHolder> certificateHolders = signedData.getCertificates().getMatches(null);
            for (final X509CertificateHolder x509CertificateHolder : certificateHolders) {
                if (!result.contains(x509CertificateHolder)) {
                    result.add(x509CertificateHolder);
                }
            }
        }
        return new JcaCertStore(result);
    }

    private Store<Encodable> getCertAttributeStore(List<CMSSignedData> cmsSignedDataList) {
        List<Encodable> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedDataList) {
            final Collection<X509AttributeCertificateHolder> attributeCertificateHolders = signedData.getAttributeCertificates().getMatches(null);
            for (final X509AttributeCertificateHolder x509AttributeCertificateHolder : attributeCertificateHolders) {
                if (!result.contains(x509AttributeCertificateHolder)) {
                    result.add(x509AttributeCertificateHolder);
                }
            }
        }
        return new CollectionStore<>(result);
    }

    private Store<Encodable> getCRLStore(List<CMSSignedData> cmsSignedDataList) {
        List<Encodable> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedDataList) {
            final Collection<X509CRLHolder> crlHolders = signedData.getCRLs().getMatches(null);
            for (final X509CRLHolder x509CRLHolder : crlHolders) {
                if (!result.contains(x509CRLHolder)) {
                    result.add(x509CRLHolder);
                }
            }
        }
        result.addAll(getOtherRevocationInfoStore(cmsSignedDataList, id_pkix_ocsp_basic));
        result.addAll(getOtherRevocationInfoStore(cmsSignedDataList, id_ri_ocsp_response));
        return new CollectionStore<>(result);
    }

    @SuppressWarnings("unchecked")
    private List<Encodable> getOtherRevocationInfoStore(List<CMSSignedData> cmsSignedDataList, ASN1ObjectIdentifier objectIdentifier) {
        List<Encodable> result = new ArrayList<>();
        for (CMSSignedData signedData : cmsSignedDataList) {
            final Collection<ASN1Encodable> basicOcsps = signedData.getOtherRevocationInfo(objectIdentifier).getMatches(null);
            for (final ASN1Encodable ocsp : basicOcsps) {
                OtherRevocationInfoFormat otherRevocationInfo = new OtherRevocationInfoFormat(objectIdentifier, ocsp);
                if (!result.contains(otherRevocationInfo)) {
                    result.add(otherRevocationInfo);
                }
            }
        }
        return result;
    }

    private List<AlgorithmIdentifier> getDigestAlgorithms(List<CMSSignedData> cmsSignedDataList) {
        List<AlgorithmIdentifier> result = new ArrayList<>();
        for (CMSSignedData cmsSignedData : cmsSignedDataList) {
            result.addAll(cmsSignedData.getDigestAlgorithmIDs());
        }
        return result;
    }

    private String getSignatureDocumentName(List<DSSDocument> signatureDocuments) {
        if (Utils.isCollectionNotEmpty(signatureDocuments)) {
            return signatureDocuments.get(0).getName();
        }
        throw new IllegalInputException("At least one signature file shall be provided for merging!");
    }

    /**
     * This method returns all signature documents extracted from given {@code ASiCContent} containers
     *
     * @param asicContents {@link ASiCContent}s
     * @return a list of {@link DSSDocument}s
     */
    protected List<DSSDocument> getAllSignatureDocuments(ASiCContent... asicContents) {
        List<DSSDocument> signatureDocuments = new ArrayList<>();
        for (ASiCContent asicContent : asicContents) {
            signatureDocuments.addAll(asicContent.getSignatureDocuments());
        }
        return signatureDocuments;
    }

}
