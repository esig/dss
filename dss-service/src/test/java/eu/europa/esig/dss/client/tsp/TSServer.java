package eu.europa.esig.dss.client.tsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * 
 * @author mpalacios
 *
 */
public class TSServer extends Thread
{
	static 
	{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static byte[] p12 = null;

	private static String P12PASSWORD = null;

    private static final int 	PORT_NO 	= 8082;

    public TSServer(byte[] p12, String p12Password) 
    {
    	TSServer.p12 	= p12;
    	P12PASSWORD 	= p12Password;
	}
    
    SSLContext createSSLContext()
	throws Exception
    {
       
        KeyStore 			serverStore = KeyStore.getInstance("PKCS12");
        //serverStore.load(TSServer.class.getResourceAsStream(P12), P12PASSWORD.toCharArray());
        serverStore.load(new ByteArrayInputStream(p12), P12PASSWORD.toCharArray());
        KeyManagerFactory 	mgrFact 	= KeyManagerFactory.getInstance("SunX509");
        mgrFact.init(serverStore, P12PASSWORD.toCharArray());
        // set up a trust manager so we can recognize the server
        TrustManagerFactory trustFact 	= TrustManagerFactory.getInstance("SunX509");
        trustFact.init(serverStore);
        // create a context and set up a socket factory
        SSLContext 	sslContext 			= SSLContext.getInstance("TLS");
        sslContext.init(mgrFact.getKeyManagers(), trustFact.getTrustManagers(), null);
        
//      for (String cipher : sslContext.getSupportedSSLParameters().getCipherSuites()) 
//      {
//			System.out.println("Cipher: " + cipher);
//		}
                
        return sslContext;
    }

    /**
     * 
     */
    public void run()
    {
        try {
        	
            SSLContext 				sslContext 	= createSSLContext();
            SSLServerSocketFactory 	fact 		= sslContext.getServerSocketFactory();
            SSLServerSocket 		sSock 		= (SSLServerSocket)fact.createServerSocket(PORT_NO);
            SSLSocket sslSock = (SSLSocket)sSock.accept();
            Thread t = new SocketThread(sslSock);
            t.start();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
    
    
    /**
     * 
     * 	@author mpalacios
     *
     */
    public static class SocketThread extends Thread
    {
    	private SSLSocket sslSock;
    	
    	public SocketThread( SSLSocket sslSock ) 
    	{
    		this.sslSock = sslSock;
		}
    	@Override
    	public void run() 
    	{
            try
            {
	    		sslSock.startHandshake();
	            byte[] request 				= readRequest(sslSock.getInputStream());
	            byte[] timeStampResponse	= processRequest(p12, "password", request);
	            sendResponse(timeStampResponse, sslSock.getOutputStream());
	            sslSock.close();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
    	}
    	
    	/**
    	 * processes a Request
    	 * @param p12
    	 * @param password
    	 * @param request
    	 * @return
    	 * @throws Exception
    	 */
        private byte[] processRequest(byte[] p12, String password, byte[] request) throws Exception 
        {
        	
    		CertificateService certificateService = new CertificateService();
			
    		MockPrivateKeyEntry privateKeyEntry = certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256);

			TimeStampRequest tstRequest = new TimeStampRequest(request);
    		
			ASN1ObjectIdentifier msgImprintOID = tstRequest.getMessageImprintAlgOID();
			
			TimeStampProducer producer = new TimeStampProducer(privateKeyEntry);
			
			return encode(producer.getTimeStampResponse(DigestAlgorithm.forOID(msgImprintOID.getId()), tstRequest.getMessageImprintDigest()).getEncoded());
		}
        
    	public static byte[] encode(byte[] berEncoded) throws IOException 
    	{
    		ASN1InputStream AIn = new ASN1InputStream(berEncoded);
    		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    		DEROutputStream dOut = new DEROutputStream(bOut);
    		dOut.writeObject(AIn.readObject());
    		dOut.close();
    		AIn.close();
    		return bOut.toByteArray();
    		
    	}
		/**
         * Reads a HTTP request
         */

    	private byte[] readRequest(InputStream in)      throws IOException
    	{
    		ByteArrayOutputStream baos = new ByteArrayOutputStream();

    		byte[] 	buf = new byte[4096];
    		int 	len = in.read(buf);
    		
    		baos.write(buf, 0, len);
    		buf = baos.toByteArray();
    		String serverHeader = new String(buf);
    		
    		int contentLengthIndex 	= serverHeader.lastIndexOf("Content-Length: ");
    		int contentLastIndex 	= serverHeader.length()-1;
    		String contentText 		= serverHeader.substring(contentLengthIndex + 16, contentLastIndex);
    		String lengthHeader 	= contentText.substring(0, contentText.indexOf("\r\n"));
    		int contentLength 		= Integer.parseInt(lengthHeader);
    		System.out.println("Content-Length: " + contentLength);
    		
    		byte[] request = new byte[contentLength];
    		System.arraycopy(buf, buf.length-contentLength, request, 0, contentLength);
    		return request;
    	}

        /**
         * Senda a response
         * @throws IOException 
         */
        
        private void sendResponse(byte[] timeStampResponse, OutputStream out) throws IOException {
        	
        	DataOutputStream dos = new DataOutputStream(out);
        	dos.write("HTTP/1.1 200 OK\r\n".getBytes());
        	dos.write("Content-Type: application/octet-stream\r\n".getBytes());
        	dos.write("\r\n".getBytes());
        	InputStream tstIS = new ByteArrayInputStream(timeStampResponse);
        	dos.write(IOUtils.toByteArray(tstIS));
        	dos.write("\r\n".getBytes());
        	dos.flush();
    	}
    }
    
    
    public static class TimeStampProducer {
    	  
    	private ASN1ObjectIdentifier policyOid;

    	private boolean useNonce;
    	
    	private SecureRandom random;
    	
    	private final PrivateKey key;

    	private final CertificateToken cert;

    	
    	public TimeStampProducer(PrivateKey tsaKey, CertificateToken tsaCert, boolean useNonce, byte[] nonceSeed, String policyOid) {
    		this.key = tsaKey;
    		this.cert = tsaCert;
    		this.useNonce = useNonce;
    		if (useNonce) {
    			if (nonceSeed != null) {
    				random = new SecureRandom(nonceSeed);
    			} else {
    				random = new SecureRandom();
    			}
    		}
    		this.policyOid = new ASN1ObjectIdentifier(policyOid);
    	}

    	/**
    	 * The default constructor for MockTSPSource.
    	 */
    	public TimeStampProducer(final MockPrivateKeyEntry entry) throws DSSException {
    		this(entry.getPrivateKey(), entry.getCertificate(), true, null, "1.234.567.890");
    	}

    	
    	public TimeStampResponse getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {

    		final String signatureAlgorithm = getSignatureAlgorithm(digestAlgorithm, digest);

    		final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
    		tsqGenerator.setCertReq(true);

    		/**
    		 * The code below guarantee that the dates of the two successive
    		 * timestamps are different. This is activated only if timestampDate is provided at
    		 * construction time
    		 */
    		Date timestampDate_ = new Date();

    		if (policyOid != null) {
    			tsqGenerator.setReqPolicy(policyOid);
    		}

    		TimeStampRequest tsRequest = null;
    		if (useNonce) {
    			final BigInteger nonce = BigInteger.valueOf(random.nextLong());
    			tsRequest = tsqGenerator.generate(new ASN1ObjectIdentifier(digestAlgorithm.getOid()), digest, nonce);
    		} else {
    			tsRequest = tsqGenerator.generate(new ASN1ObjectIdentifier(digestAlgorithm.getOid()), digest);
    		}

    		try {
    			final ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).build(key);
    			final JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert.getCertificate());

    			// that to make sure we generate the same timestamp data for the
    			// same timestamp date
    			AttributeTable signedAttributes = new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Object>());
    			signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new Time(timestampDate_));
    			final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributes);
    			AttributeTable unsignedAttributes = new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Object>());
    			final SimpleAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributes);

    			final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
    			SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
    			sigInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
    			sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedAttributeGenerator);
    			final SignerInfoGenerator sig = sigInfoGeneratorBuilder.build(sigGen, certHolder);

    			final DigestCalculator sha1DigestCalculator = DSSRevocationUtils.getSHA1DigestCalculator();

    			final TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(sig, sha1DigestCalculator, policyOid);
    			final Set<X509Certificate> singleton = new HashSet<X509Certificate>();
    			singleton.add(cert.getCertificate());
    			tokenGenerator.addCertificates(new JcaCertStore(singleton));
    			final TimeStampResponseGenerator generator = new TimeStampResponseGenerator(tokenGenerator, TSPAlgorithms.ALLOWED);

    			Date responseDate = new Date();
    			TimeStampResponse tsResponse = generator.generate(tsRequest, BigInteger.ONE, responseDate);
    			
    			return tsResponse;
    		} catch (OperatorCreationException e) {
    			throw new DSSException(e);
    		} catch (CertificateEncodingException e) {
    			throw new DSSException(e);
    		} catch (TSPException e) {
    			throw new DSSException(e);
    		}
    	}

    	private String getSignatureAlgorithm(DigestAlgorithm algorithm, byte[] digest) {
    		String signatureAlgorithm;
    		if (DigestAlgorithm.SHA1.equals(algorithm)) {
    			signatureAlgorithm = "SHA1withRSA";
    			if (digest.length != 20) {
    				throw new IllegalArgumentException("Not valid size for a SHA1 digest : " + digest.length + " bytes");
    			}
    		} else if (DigestAlgorithm.SHA256.equals(algorithm)) {
    			signatureAlgorithm = "SHA256withRSA";
    			if (digest.length != 32) {
    				throw new IllegalArgumentException("Not valid size for a SHA256 digest : " + digest.length + " bytes");
    			}
    		} else {

    			throw new UnsupportedOperationException("No support for " + algorithm);
    		}
    		return signatureAlgorithm;
    	}
    	
    }

}
