package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.Test;

public class SerializationTest {

	@Test
	public void testSerializationSignatureLevel() throws Exception {
		SignatureLevel asicEBaselineB = SignatureLevel.XAdES_BASELINE_B;
		byte[] serialized = serialize(asicEBaselineB);
		SignatureLevel unserialized = unserialize(serialized, SignatureLevel.class);
		assertEquals(asicEBaselineB, unserialized);
	}

	@Test
	public void testSerializationSignaturePackaging() throws Exception {
		SignaturePackaging detached = SignaturePackaging.DETACHED;
		byte[] serialized = serialize(detached);
		SignaturePackaging unserialized = unserialize(serialized, SignaturePackaging.class);
		assertEquals(detached, unserialized);
	}

	@Test
	public void testSerializationDigestAlgorithm() throws Exception {
		DigestAlgorithm sha1 = DigestAlgorithm.SHA1;
		byte[] serialized = serialize(sha1);
		DigestAlgorithm unserialized = unserialize(serialized, DigestAlgorithm.class);
		assertEquals(sha1, unserialized);
	}

	@Test
	public void testSerializationEncryptionAlgorithm() throws Exception {
		EncryptionAlgorithm dsa = EncryptionAlgorithm.DSA;
		byte[] serialized = serialize(dsa);
		EncryptionAlgorithm unserialized = unserialize(serialized, EncryptionAlgorithm.class);
		assertEquals(dsa, unserialized);
	}

	@Test
	public void testSerializationSignatureAlgorithm() throws Exception {
		SignatureAlgorithm dsa_sha1 = SignatureAlgorithm.DSA_SHA1;
		byte[] serialized = serialize(dsa_sha1);
		SignatureAlgorithm unserialized = unserialize(serialized, SignatureAlgorithm.class);
		assertEquals(dsa_sha1, unserialized);
	}

	@Test
	public void testSerializationTimestampParameters() throws Exception {
		TimestampParameters timestampParams = new TimestampParameters();
		byte[] serialized = serialize(timestampParams);
		TimestampParameters unserialized = unserialize(serialized, TimestampParameters.class);
		assertEquals(timestampParams, unserialized);
	}

	@Test
	public void testSerializationToBeSigned() throws Exception {
		ToBeSigned toBeSigned = new ToBeSigned();
		toBeSigned.setBytes(new byte[] { 1, 2, 3, 4 });
		byte[] serialized = serialize(toBeSigned);
		ToBeSigned unserialized = unserialize(serialized, ToBeSigned.class);
		assertEquals(toBeSigned, unserialized);
	}

	@Test
	public void testSerializationSignatureValue() throws Exception {
		SignatureValue signatureValue = new SignatureValue();
		signatureValue.setAlgorithm(SignatureAlgorithm.DSA_SHA256);
		signatureValue.setValue(new byte[] { 1, 2, 3, 4 });
		byte[] serialized = serialize(signatureValue);
		SignatureValue unserialized = unserialize(serialized, SignatureValue.class);
		assertEquals(signatureValue, unserialized);
	}

	@Test
	public void testSerializationPolicy() throws Exception {
		Policy signaturePolicy = new Policy();
		signaturePolicy.setDescription("description");
		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.MD5);
		signaturePolicy.setDigestValue(new byte[] { 1, 2 });
		signaturePolicy.setId("id");
		signaturePolicy.setSpuri("uri");

		byte[] serialized = serialize(signaturePolicy);
		Policy unserialized = unserialize(serialized, Policy.class);
		assertEquals(signaturePolicy, unserialized);
	}

	@Test
	public void testSerializationBLevel() throws Exception {
		BLevelParameters blevel = new BLevelParameters();
		blevel.setSigningDate(new Date());
		List<String> commitmentTypeIndication = new ArrayList<String>();
		commitmentTypeIndication.add("Test commitment");
		blevel.setCommitmentTypeIndications(commitmentTypeIndication);

		byte[] serialized = serialize(blevel);
		BLevelParameters unserialized = unserialize(serialized, BLevelParameters.class);
		assertEquals(blevel, unserialized);
	}

	@Test
	public void testSerializationSignerLocation() throws Exception {
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setCountry("country");
		signerLocation.setLocality("locality");
		List<String> postalAddress = new ArrayList<String>();
		postalAddress.add("Postal address");
		signerLocation.setPostalAddress(postalAddress);
		signerLocation.setPostalCode("postal code");
		signerLocation.setStateOrProvince("state");

		byte[] serialized = serialize(signerLocation);
		SignerLocation unserialized = unserialize(serialized, SignerLocation.class);
		assertEquals(signerLocation, unserialized);
	}

	@Test
	public void testSerialization2() throws Exception {
		MockSignatureParameters testObj = new MockSignatureParameters();
		testObj.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		testObj.setSignaturePackaging(SignaturePackaging.DETACHED);
		testObj.setSignWithExpiredCertificate(false);
		testObj.setDigestAlgorithm(DigestAlgorithm.SHA1);
		testObj.bLevel().setSigningDate(new Date());
		List<String> commitmentTypeIndication = new ArrayList<String>();
		commitmentTypeIndication.add("Test commitment");
		testObj.bLevel().setCommitmentTypeIndications(commitmentTypeIndication);
		Policy signaturePolicy = new Policy();
		signaturePolicy.setDescription("description");
		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.MD5);
		signaturePolicy.setDigestValue(new byte[] { 1, 2 });
		signaturePolicy.setId("id");
		signaturePolicy.setSpuri("uri");
		testObj.bLevel().setSignaturePolicy(signaturePolicy);
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setCountry("country");
		signerLocation.setLocality("locality");
		List<String> postalAddress = new ArrayList<String>();
		postalAddress.add("Postal address");
		signerLocation.setPostalAddress(postalAddress);
		signerLocation.setPostalCode("postal code");
		signerLocation.setStateOrProvince("state");
		testObj.bLevel().setSignerLocation(signerLocation);

		byte[] serialized = serialize(testObj);
		MockSignatureParameters unserialized = unserialize(serialized, MockSignatureParameters.class);

		assertEquals(testObj, unserialized);
	}

	private static <T extends Serializable> byte[] serialize(T obj) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(obj);
		oos.close();
		return baos.toByteArray();
	}

	private static <T extends Serializable> T unserialize(byte[] b, Class<T> clazz) throws Exception {
		ByteArrayInputStream bais = new ByteArrayInputStream(b);
		ObjectInputStream ois = new ObjectInputStream(bais);
		Object o = ois.readObject();
		return clazz.cast(o);
	}

}
