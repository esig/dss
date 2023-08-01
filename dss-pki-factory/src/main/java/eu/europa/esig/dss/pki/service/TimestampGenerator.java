package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.utils.PkiUtils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


public class TimestampGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(TimestampGenerator.class);
    private static TimestampGenerator instance = null;
    private static final SecureRandom random = new SecureRandom();
    private static CertificateEntityService entityService = null;

    private TimestampGenerator() {
    }

    public static TimestampGenerator getInstance() {
        if (instance == null) {
            synchronized (TimestampGenerator.class) {
                instance = new TimestampGenerator();
                entityService = CertificateEntityService.getInstance();
            }
        }
        return instance;
    }


    private TimeStampResponseGenerator initResponseGenerator(String id, TimeStampRequest tsr)
            throws OperatorCreationException, TSPException, CertificateEncodingException {

        X509CertificateHolder certificate = entityService.getCertificate(id);
        PrivateKey privateKey = entityService.getPrivateKey(id);
        X509CertificateHolder[] certificateChain = entityService.getCertificateChain(id);
        DBCertEntity certEntity = entityService.getCertificateEntity(id);

        String sigAlgoName = PkiUtils.getAlgorithmString(certEntity.getPrivateKeyAlgo(), certEntity.getDigestAlgo(), certEntity.isPss());

        Set<ASN1ObjectIdentifier> accepted = new HashSet<>();
        accepted.add(TSPAlgorithms.SHA1);
        accepted.add(TSPAlgorithms.SHA224);
        accepted.add(TSPAlgorithms.SHA256);
        accepted.add(TSPAlgorithms.SHA384);
        accepted.add(TSPAlgorithms.SHA512);

        accepted.add(NISTObjectIdentifiers.id_sha3_512);

        AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(tsr.getMessageImprintAlgOID());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlgoName).build(privateKey);

        SignerInfoGenerator infoGenerator = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider()).build(signer, certificate);

        DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(digestAlgorithmIdentifier);

        TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(infoGenerator, digestCalculator, new ASN1ObjectIdentifier("1.2.3.4"));
        tokenGenerator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

        return new TimeStampResponseGenerator(tokenGenerator, accepted);
    }

    public byte[] getTimestamp(String id, Date date, InputStream inputStream) {
        try {
            TimeStampRequest timeStampRequest = getTimeStampRequest(inputStream);

            TimeStampResponseGenerator gen = initResponseGenerator(id, timeStampRequest);
            TimeStampResponse response = generateResponse(gen, new BigInteger(128, random), timeStampRequest, date);
            return response.getEncoded();
        } catch (CertificateEncodingException | TSPException | OperatorCreationException | IOException e) {
            LOG.error("Unable to generate the timestamp response", e);
            throw new Error500Exception("Unable to generate the timestamp response");
        }
    }

    public byte[] getFailedTimestamp(String id, InputStream inputStream) {
        try {
            TimeStampRequest timeStampRequest = getTimeStampRequest(inputStream);

            TimeStampResponseGenerator gen = initResponseGenerator(id, timeStampRequest);
            TimeStampResponse response = generateFailedResponse(gen);
            return response.getEncoded();
        } catch (CertificateEncodingException | TSPException | OperatorCreationException | IOException e) {
            LOG.error("Unable to generate the failed timestamp response", e);
            throw new Error500Exception("Unable to generate the failed timestamp response");
        }
    }

    private TimeStampRequest getTimeStampRequest(InputStream inputStream) {
        try {
            return new TimeStampRequest(inputStream);
        } catch (IOException e) {
            LOG.error("Unable to parse the timestamp request", e);
            throw new Error500Exception("Unable to parse the timestamp request");
        }
    }

    private TimeStampResponse generateResponse(TimeStampResponseGenerator gen, BigInteger serialNumber, TimeStampRequest tsreq, Date date) throws TSPException {
        return gen.generate(tsreq, serialNumber, date);
    }

    private TimeStampResponse generateFailedResponse(TimeStampResponseGenerator gen) throws TSPException {
        return gen.generateFailResponse(PKIStatus.REJECTION, PKIFailureInfo.systemFailure, "Error for testing");
    }

}