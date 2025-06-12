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
