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
package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Implementation of a {@code CMS} based on a parsed content.
 *
 */
public class CMSSignedDataStream implements CMS {

    /** Original document providing on parsing */
    private DSSDocument cmsDocument;

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
     * Default constructor to create an empty instance on CMS creation
     */
    public CMSSignedDataStream() {
        // empty
    }

    /**
     * Constructor to create a copy of {@code cms}
     *
     * @param cms {@link CMSSignedDataStream}
     */
    public CMSSignedDataStream(CMSSignedDataStream cms) {
        this.cmsDocument = cms.cmsDocument;
        this.version = cms.version;
        this.digestAlgorithmIDs = cms.digestAlgorithmIDs != null ? new HashSet<>(cms.digestAlgorithmIDs) : null;
        this.isDetachedSignature = cms.isDetachedSignature;
        this.signedContentType = cms.signedContentType;
        this.signedContent = cms.signedContent;
        this.certificates = cms.certificates != null ? new CollectionStore<>(cms.certificates.getMatches(null)) : null;
        this.attributeCertificates = cms.attributeCertificates != null ? new CollectionStore<>(cms.attributeCertificates.getMatches(null)) : null;
        this.crls = cms.crls != null ? new CollectionStore<>(cms.crls.getMatches(null)) : null;
        this.ocspResponseStore = cms.ocspResponseStore != null ? new CollectionStore<>(cms.ocspResponseStore.getMatches(null)) : null;
        this.ocspBasicStore = cms.ocspBasicStore != null ? new CollectionStore<>(cms.ocspBasicStore.getMatches(null)) : null;
        this.signerInfos = cms.signerInfos != null ? new SignerInformationStore(cms.signerInfos.getSigners()) : null;
    }

    /**
     * This constructor is used to create an instance of {@code CMSSignedDataStream} on parsing of
     * an existing CMS document
     *
     * @param cmsDocument {@link DSSDocument} original document provided on parsing
     */
    public CMSSignedDataStream(DSSDocument cmsDocument) {
        this.cmsDocument = cmsDocument;
    }

    /**
     * Gets the original CMS document used to create the CMS
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getCMSDocument() {
        return cmsDocument;
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
         * Due to a limitation of CMSSignedDataStreamGenerator
         * (see {@link <a href="https://github.com/bcgit/bc-java/issues/1482">https://github.com/bcgit/bc-java/issues/1482</a> })
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

    @Override
    public byte[] getEncoded() {
        final String encoding = CMSUtils.getContentInfoEncoding(this);
        if (!ASN1Encoding.DER.equals(encoding) && !ASN1Encoding.DL.equals(encoding) && !ASN1Encoding.BER.equals(encoding)) {
            throw new UnsupportedOperationException(String.format("The encoding of type '%s' is not supported!", encoding));
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            // ContentInfo
            BERSequenceGenerator sGen = new BERSequenceGenerator(baos);
            sGen.addObject(CMSObjectIdentifiers.signedData);

            // Signed Data
            BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

            // Version
            sigGen.addObject(new ASN1Integer(version));

            CMSUtils.writeSignedDataDigestAlgorithmsEncoded(this, sigGen.getRawOutputStream());
            CMSUtils.writeContentInfoEncoded(this, sigGen.getRawOutputStream());
            CMSUtils.writeSignedDataCertificatesEncoded(this, sigGen.getRawOutputStream());
            CMSUtils.writeSignedDataCRLsEncoded(this, sigGen.getRawOutputStream());
            CMSUtils.writeSignedDataSignerInfosEncoded(this, sigGen.getRawOutputStream());

            sigGen.close();
            sGen.close();

            byte[] bytes = baos.toByteArray();
            if (ASN1Encoding.DER.equals(encoding)) {
                bytes = DSSASN1Utils.getDEREncoded(bytes);
            } else if (ASN1Encoding.DL.equals(encoding)) {
                bytes = DSSASN1Utils.getDLEncoded(bytes);
            }
            // otherwise keep BER
            return bytes;

        } catch (IOException e) {
            throw new DSSException("Unable to return CMS encoded", e);
        }
    }

}
