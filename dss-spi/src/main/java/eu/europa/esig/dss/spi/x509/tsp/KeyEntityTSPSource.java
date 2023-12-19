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
package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * TSPSource implementation allowing to configure issuance of a time-stamp using a local {@code KeyStore}
 */
public class KeyEntityTSPSource implements TSPSource {

    private static final long serialVersionUID = -5082887845359355029L;

    /**
     * The private key to be used to sign a time-stamp token
     */
    private PrivateKey privateKey;

    /**
     * The certificate representing a time-stamp issuer
     */
    private X509Certificate certificate;

    /**
     * Certificate chain associated with the {@code certificate}
     */
    private List<X509Certificate> certificateChain;

    /**
     * SecureRandom used to calculate a serial number for a timestamp
     */
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Collection of digest algorithms accepted by the current TSP source in the request
     */
    private Collection<DigestAlgorithm> acceptedDigestAlgorithms =
            Arrays.asList(DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512);

    /**
     * The TSA policy
     */
    private String tsaPolicy;

    /**
     * The static production date of the timestamp
     */
    protected Date productionTime;

    /**
     * The Digest Algorithm of the signature of the created time-stamp token
     */
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    /**
     * Encryption algorithm of the signature of the OCSP response
     */
    private EncryptionAlgorithm encryptionAlgorithm;

    /**
     * Mask Generation Function of the signature of the OCSP response
     */
    private MaskGenerationFunction maskGenerationFunction;

    /**
     * Default constructor instantiating empty configuration of the KeyEntityTSPSource
     */
    protected KeyEntityTSPSource() {
        // empty
    }

    /**
     * Constructor instantiating the key store content and key entry data
     *
     * @param ksContent        byte array representing the key store content
     * @param ksType           {@link String} representing the type of the key store
     * @param ksPassword       char array representing a password from the key store
     * @param alias            {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     */
    public KeyEntityTSPSource(byte[] ksContent, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) {
        this(loadKeyStore(new ByteArrayInputStream(ksContent), ksType, ksPassword), alias, keyEntryPassword);
    }

    /**
     * Constructor instantiating the key store path location and key entry data
     *
     * @param ksPath           {@link String} representing the path to the key store
     * @param ksType           {@link String} representing the type of the key store
     * @param ksPassword       char array representing a password from the key store
     * @param alias            {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     * @throws IOException if not able to load the key store file
     */
    public KeyEntityTSPSource(String ksPath, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) throws IOException {
        this(new File(ksPath), ksType, ksPassword, alias, keyEntryPassword);
    }

    /**
     * Constructor instantiating the key store File and key entry data
     *
     * @param ksFile           {@link File} key store file
     * @param ksType           {@link String} representing the type of the key store
     * @param ksPassword       char array representing a password from the key store
     * @param alias            {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     * @throws IOException if not able to load the key store file
     */
    public KeyEntityTSPSource(File ksFile, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) throws IOException {
        this(Files.newInputStream(ksFile.toPath()), ksType, ksPassword, alias, keyEntryPassword);
    }

    /**
     * Constructor instantiating the key store InputStream and key entry data
     *
     * @param ksIs             {@link InputStream} representing the key store content
     * @param ksType           {@link String} representing the type of the key store
     * @param ksPassword       char array representing a password from the key store
     * @param alias            {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     */
    public KeyEntityTSPSource(InputStream ksIs, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) {
        this(loadKeyStore(ksIs, ksType, ksPassword), alias, keyEntryPassword);
    }

    private static KeyStore loadKeyStore(InputStream keyStoreIs, String ksType, char[] keyStorePassword) {
        try (InputStream is = keyStoreIs) {
            KeyStore keyStore = KeyStore.getInstance(ksType);
            keyStore.load(is, keyStorePassword);
            return keyStore;
        } catch (Exception e) {
            throw new DSSException("Unable to instantiate KeyStore", e);
        }
    }

    /**
     * Constructor instantiating the key store and key entry data
     *
     * @param keyStore         {@link KeyStore}
     * @param alias            {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     */
    public KeyEntityTSPSource(KeyStore keyStore, String alias, char[] keyEntryPassword) {
        Objects.requireNonNull(keyStore,"KeyStore is not defined!");
        Objects.requireNonNull(alias,"Alias is not defined!");
        Objects.requireNonNull(keyEntryPassword,"KeyEntry Password is not defined!");
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(keyStore, alias, keyEntryPassword);
        this.privateKey = privateKeyEntry.getPrivateKey();
        this.certificate = (X509Certificate) privateKeyEntry.getCertificate();
        this.certificateChain = Arrays.stream(privateKeyEntry.getCertificateChain()).map(c -> (X509Certificate) c).collect(Collectors.toList());
    }

    private static KeyStore.PrivateKeyEntry getPrivateKeyEntry(KeyStore keyStore, String alias, char[] keyEntryPassword) {
        try {
            if (!keyStore.isKeyEntry(alias)) {
                throw new IllegalArgumentException(String.format("No related/supported key entry found for alias '%s'!", alias));
            }
            if (!keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                throw new IllegalArgumentException(String.format("No key entry found for alias '%s' is not instance of a PrivateKeyEntry!", alias));
            }

            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(keyEntryPassword));
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new DSSException(String.format("Unable to recover the key entry with alias '%s'. Reason : %s", alias, e.getMessage()), e);
        }
    }

    /**
     * Constructor to instantiate KeyEntityTSPSource with the given {@code PrivateKey} and
     * the corresponding {@code certificateToken} and {@code certificateChain}
     *
     * @param privateKey       {@link PrivateKey} representing a key t be used to sing the time-stamp token
     * @param certificateToken {@link CertificateToken} representing a time-stamp issuer certificate associated
     *                         with the {@code privateKey}
     * @param certificateChain a list of {@link CertificateToken}s representing a certificate chain
     *                         for {@code certificateToken} to be added within the time-stamp
     */
    public KeyEntityTSPSource(PrivateKey privateKey, CertificateToken certificateToken, List<CertificateToken> certificateChain) {
        this(privateKey, certificateToken.getCertificate(), certificateChain.stream().map(CertificateToken::getCertificate).collect(Collectors.toList()));
    }

    /**
     * Constructor to instantiate KeyEntityTSPSource with the given {@code PrivateKey} and
     * the corresponding {@code certificate} and {@code certificateChain}
     *
     * @param privateKey       {@link PrivateKey} representing a key t be used to sing the time-stamp token
     * @param certificate {@link X509Certificate} representing a time-stamp issuer certificate associated
     *                         with the {@code privateKey}
     * @param certificateChain a list of {@link X509Certificate}s representing a certificate chain
     *                         for {@code certificateToken} to be added within the time-stamp
     */
    public KeyEntityTSPSource(PrivateKey privateKey, X509Certificate certificate, List<X509Certificate> certificateChain) {
        Objects.requireNonNull(privateKey,"PrivateKey is not defined!");
        Objects.requireNonNull(certificate,"Certificate is not defined!");
        Objects.requireNonNull(certificateChain,"Certificate chain is not defined!");
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.certificateChain = certificateChain;
    }

    /**
     * Sets the private key used to sign the time-stamp token
     *
     * @param privateKey {@link PrivateKey}
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Sets a time-stamp issuer certificate
     *
     * @param certificate {@link X509Certificate}
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Sets a certificate chain to be embedded within the time-stamp token
     *
     * @param certificateChain a list of {@link CertificateToken}s
     */
    public void setCertificateChain(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * Sets the TSA policy
     * NOTE: The property is mandatory for TimeStampToken generation.
     *
     * @param tsaPolicy {@link String}
     */
    public void setTsaPolicy(String tsaPolicy) {
        this.tsaPolicy = tsaPolicy;
    }

    /**
     * Sets a collection of digest algorithms to be accepted within timestamp request
     * Default: SHA-224, SHA-256, SHA-384, SHA-512
     *
     * @param digestAlgorithms a collection of {@link DigestAlgorithm}s
     */
    public void setAcceptedDigestAlgorithms(Collection<DigestAlgorithm> digestAlgorithms) {
        this.acceptedDigestAlgorithms = digestAlgorithms;
    }

    /**
     * Gets the production time of the time-stamp
     *
     * @return {@link Date}
     */
    protected Date getProductionTime() {
        if (productionTime == null) {
            return new Date();
        }
        return productionTime;
    }

    /**
     * Sets a production time of the timestamp.
     * NOTE: if not defined, the current time will be used.
     *
     * @param productionTime {@link Date}
     */
    public void setProductionTime(Date productionTime) {
        this.productionTime = productionTime;
    }

    /**
     * Sets the digest algorithm of the signature of the generated time-stamp token
     * Default: DigestAlgorithm.SHA256
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Sets the encryption algorithm to be used on time-stamp's signature generation.
     * NOTE: the encryptionAlgorithm, when defined, shall be compatible with the encryption algorithm used by the target key!
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     */
    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    /**
     * Sets the mask generation function to be applied on a time-stamp signing.
     * NOTE: the mask generation function should be compatible with the given encryption algorithm!
     *
     * @param maskGenerationFunction {@link MaskGenerationFunction}
     */
    public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
        this.maskGenerationFunction = maskGenerationFunction;
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
        Objects.requireNonNull(privateKey, "PrivateKey is not defined! Use #setPrivateKey method.");
        Objects.requireNonNull(certificate, "Certificate is not defined! Use #setCertificate method.");
        Objects.requireNonNull(certificateChain, "Certificate chain is not defined! Use #setCertificateChain method.");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm is not defined!");
        Objects.requireNonNull(digest, "digest is not defined!");
        Objects.requireNonNull(tsaPolicy, "TSAPolicy OID is not defined! Use #setTsaPolicy method.");

        if (!acceptedDigestAlgorithms.contains(digestAlgorithm)) {
            throw new DSSException(String.format("DigestAlgorithm '%s' is not supported by the KeyEntityTSPSource implementation!", digestAlgorithm));
        }

        try {
            TimeStampRequest request = createRequest(digestAlgorithm, digest);
            TimeStampResponse response = generateResponse(request, digestAlgorithm);
            return new TimestampBinary(response.getTimeStampToken().getEncoded());

        } catch (IOException | TSPException e) {
            throw new DSSException(String.format("Unable to generate a timestamp. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Creates a request for a time-stamp token generation
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used to compute hash to be time-stamped
     * @param digest byte array representing hash to be time-stamped
     * @return {@link TimeStampRequest}
     */
    protected TimeStampRequest createRequest(DigestAlgorithm digestAlgorithm, byte[] digest) {
        final TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.setCertReq(true);
        return requestGenerator.generate(getASN1ObjectIdentifier(digestAlgorithm), digest);
    }

    private Set<ASN1ObjectIdentifier> getAcceptedDigestAlgorithmIdentifiers() {
        Set<ASN1ObjectIdentifier> result = new HashSet<>();
        for (DigestAlgorithm digestAlgorithm : acceptedDigestAlgorithms) {
            result.add(getASN1ObjectIdentifier(digestAlgorithm));
        }
        return result;
    }

    private ASN1ObjectIdentifier getASN1ObjectIdentifier(DigestAlgorithm digestAlgorithm) {
        return getASN1ObjectIdentifier(digestAlgorithm.getOid());
    }

    private ASN1ObjectIdentifier getASN1ObjectIdentifier(String oid) {
        return new ASN1ObjectIdentifier(oid);
    }

    /**
     * Returns the target signature algorithm to be used to time-stamp generation
     *
     * @return {@link String} signature algorithm name
     */
    protected SignatureAlgorithm getSignatureAlgorithm() {
        EncryptionAlgorithm keyAlgorithm = EncryptionAlgorithm.forKey(privateKey);
        if (this.encryptionAlgorithm != null) {
            if (!this.encryptionAlgorithm.isEquivalent(keyAlgorithm)) {
                throw new IllegalArgumentException(String.format(
                        "Defined EncryptionAlgorithm '%s' is not equivalent to the one returned by time-stamp issuer '%s'", encryptionAlgorithm, keyAlgorithm));
            }
            keyAlgorithm = encryptionAlgorithm;
        }
        return SignatureAlgorithm.getAlgorithm(keyAlgorithm, digestAlgorithm, maskGenerationFunction);
    }

    /**
     * This method generates a timestamp response
     *
     * @param request           {@link TimeStampRequest}
     * @param digestAlgorithm   {@link DigestAlgorithm} used to generate the time-stamp
     * @return {@link TimeStampResponse}
     * @throws TSPException if an error occurs during the timestamp response generation
     */
    protected TimeStampResponse generateResponse(TimeStampRequest request, DigestAlgorithm digestAlgorithm) throws TSPException {
        final Date productionTime = getProductionTime();
        TimeStampResponseGenerator responseGenerator = initResponseGenerator(digestAlgorithm, productionTime);
        BigInteger timeStampSerialNumber = getTimeStampSerialNumber();
        return buildResponse(responseGenerator, request, timeStampSerialNumber, productionTime);
    }

    /**
     * This method initializes the {@code TimeStampResponseGenerator}
     *
     * @param digestAlgorithm {@link DigestAlgorithm} used to generate the message-imprint
     * @param getTime {@link Date} production time of the time-stamp
     * @return {@link TimeStampResponseGenerator}
     */
    protected TimeStampResponseGenerator initResponseGenerator(DigestAlgorithm digestAlgorithm, Date getTime) {
        try {
            SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm();
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm.getJCEId()).build(privateKey);

            X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
            SignerInfoGenerator infoGenerator = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                    .setSignedAttributeGenerator(getSignedAttributeGenerator(getTime)).build(signer, certificateHolder);

            AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(getASN1ObjectIdentifier(digestAlgorithm));
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(digestAlgorithmIdentifier);

            TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(infoGenerator, digestCalculator, getASN1ObjectIdentifier(tsaPolicy));

            tokenGenerator.addCertificates(new JcaCertStore(certificateChain));

            return new TimeStampResponseGenerator(tokenGenerator, getAcceptedDigestAlgorithmIdentifiers());

        } catch (CertificateEncodingException | OperatorCreationException | TSPException e) {
            throw new DSSException(String.format("Unable to generate a timestamp. Reason : %s", e.getMessage()), e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns generator for signed attributes of a time-stamp
     *
     * @param getTime {@link Date} production time of the time-stamp
     * @return {@link CMSAttributeTableGenerator}
     */
    protected CMSAttributeTableGenerator getSignedAttributeGenerator(Date getTime) {
        return new DefaultSignedAttributeTableGenerator() {

            @Override
            protected Hashtable createStandardAttributeTable(Map map) {
                Hashtable hashtable = super.createStandardAttributeTable(map);

                // Ensure the same productionTime is used
                if (getTime != null) {
                    Attribute attr = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(getTime)));
                    hashtable.put(CMSAttributes.signingTime, attr);
                }

                return hashtable;
            }

        };
    }

    /**
     * Generates a time-stamp response
     *
     * @param responseGenerator {@link TimeStampResponseGenerator}
     * @param request {@link TimeStampRequest}
     * @param timeStampSerialNumber {@link BigInteger}
     * @param productionTime {@link Date} representing a time-stamp's generation time
     * @return {@link TimeStampResponse}
     * @throws TSPException if an error occurs on time-stamp generation
     */
    protected TimeStampResponse buildResponse(TimeStampResponseGenerator responseGenerator, TimeStampRequest request,
                                              BigInteger timeStampSerialNumber, Date productionTime) throws TSPException {
        return responseGenerator.generate(request, timeStampSerialNumber, productionTime);
    }

    /**
     * Generates a serial number of the produced timestamp token
     *
     * @return {@link BigInteger} serial number
     */
    protected BigInteger getTimeStampSerialNumber() {
        return new BigInteger(128, secureRandom);
    }

}
