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
package eu.europa.esig.dss.cms.object;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Set;

/**
 * Implementation of a {@code CMS} based on a BouncyCastle {@code org.bouncycastle.cms.CMSSignedData}
 *
 */
public class CMSSignedDataObject implements CMS {

    /**
     * Wrapped {@code CMSSignedData}
     */
    private final CMSSignedData cmsSignedData;

    /**
     * Default constructor
     *
     * @param cmsSignedData {@link CMSSignedData}
     */
    public CMSSignedDataObject(final CMSSignedData cmsSignedData) {
        this.cmsSignedData = cmsSignedData;
    }

    /**
     * Gets a {@code CMSSignedData}
     *
     * @return {@link CMSSignedData}
     */
    public CMSSignedData getCMSSignedData() {
        return cmsSignedData;
    }

    @Override
    public int getVersion() {
        return cmsSignedData.getVersion();
    }

    @Override
    public Set<AlgorithmIdentifier> getDigestAlgorithmIDs() {
        return cmsSignedData.getDigestAlgorithmIDs();
    }

    @Override
    public boolean isDetachedSignature() {
        return cmsSignedData.isDetachedSignature();
    }

    @Override
    public ASN1ObjectIdentifier getSignedContentType() {
        if (cmsSignedData.getSignedContentTypeOID() != null) {
            return new ASN1ObjectIdentifier(cmsSignedData.getSignedContentTypeOID());
        }
        return null;
    }

    @Override
    public DSSDocument getSignedContent() {
        if (cmsSignedData.getSignedContent() != null) {
            return getSignedContent(cmsSignedData.getSignedContent());
        }
        return null;
    }

    /**
     * This method returns the signed content extracted from a CMSTypedData
     *
     * @param cmsTypedData
     *            {@code CMSTypedData} cannot be null
     * @return {@link DSSDocument} the signed content extracted from {@code CMSTypedData}
     */
    private DSSDocument getSignedContent(final CMSTypedData cmsTypedData) {
        if (cmsTypedData == null) {
            throw new DSSException("CMSTypedData is null (should be a detached signature)");
        }
        try (ByteArrayOutputStream originalDocumentData = new ByteArrayOutputStream()) {
            cmsTypedData.write(originalDocumentData);
            return new InMemoryDocument(originalDocumentData.toByteArray());
        } catch (CMSException | IOException e) {
            throw new DSSException(e);
        }
    }

    @Override
    public Store<X509CertificateHolder> getCertificates() {
        return cmsSignedData.getCertificates();
    }

    @Override
    public Store<X509CRLHolder> getCRLs() {
        return cmsSignedData.getCRLs();
    }

    @Override
    public Store<X509AttributeCertificateHolder> getAttributeCertificates() {
        return cmsSignedData.getAttributeCertificates();
    }

    @Override
    public Store<?> getOcspResponseStore() {
        return cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
    }

    @Override
    public Store<?> getOcspBasicStore() {
        return cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
    }

    @Override
    public SignerInformationStore getSignerInfos() {
        return cmsSignedData.getSignerInfos();
    }

    @Override
    public byte[] getDEREncoded() {
        return DSSASN1Utils.getDEREncoded(cmsSignedData);
    }

    @Override
    public byte[] getEncoded() {
        return DSSASN1Utils.getEncoded(cmsSignedData);
    }

}
