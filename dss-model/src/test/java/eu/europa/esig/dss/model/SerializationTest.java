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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SerializationTest {

	@Test
	void testSerializationSignatureLevel() throws Exception {
		SignatureLevel asicEBaselineB = SignatureLevel.XAdES_BASELINE_B;
		byte[] serialized = serialize(asicEBaselineB);
		SignatureLevel unserialized = unserialize(serialized, SignatureLevel.class);
		assertEquals(asicEBaselineB, unserialized);
	}

	@Test
	void testSerializationSignaturePackaging() throws Exception {
		SignaturePackaging detached = SignaturePackaging.DETACHED;
		byte[] serialized = serialize(detached);
		SignaturePackaging unserialized = unserialize(serialized, SignaturePackaging.class);
		assertEquals(detached, unserialized);
	}

	@Test
	void testSerializationDigestAlgorithm() throws Exception {
		DigestAlgorithm sha1 = DigestAlgorithm.SHA1;
		byte[] serialized = serialize(sha1);
		DigestAlgorithm unserialized = unserialize(serialized, DigestAlgorithm.class);
		assertEquals(sha1, unserialized);
	}

	@Test
	void testSerializationEncryptionAlgorithm() throws Exception {
		EncryptionAlgorithm dsa = EncryptionAlgorithm.DSA;
		byte[] serialized = serialize(dsa);
		EncryptionAlgorithm unserialized = unserialize(serialized, EncryptionAlgorithm.class);
		assertEquals(dsa, unserialized);
	}

	@Test
	void testSerializationSignatureAlgorithm() throws Exception {
		SignatureAlgorithm dsa_sha1 = SignatureAlgorithm.DSA_SHA1;
		byte[] serialized = serialize(dsa_sha1);
		SignatureAlgorithm unserialized = unserialize(serialized, SignatureAlgorithm.class);
		assertEquals(dsa_sha1, unserialized);
	}

	@Test
	void testSerializationTimestampParameters() throws Exception {
		TimestampParameters timestampParams = new MockTimestampParameters();
		byte[] serialized = serialize(timestampParams);
		TimestampParameters unserialized = unserialize(serialized, TimestampParameters.class);
		assertEquals(timestampParams, unserialized);
	}

	@Test
	void testSerializationToBeSigned() throws Exception {
		ToBeSigned toBeSigned = new ToBeSigned();
		toBeSigned.setBytes(new byte[] { 1, 2, 3, 4 });
		byte[] serialized = serialize(toBeSigned);
		ToBeSigned unserialized = unserialize(serialized, ToBeSigned.class);
		assertEquals(toBeSigned, unserialized);
	}

	@Test
	void testSerializationSignatureValue() throws Exception {
		SignatureValue signatureValue = new SignatureValue();
		signatureValue.setAlgorithm(SignatureAlgorithm.DSA_SHA256);
		signatureValue.setValue(new byte[] { 1, 2, 3, 4 });
		byte[] serialized = serialize(signatureValue);
		SignatureValue unserialized = unserialize(serialized, SignatureValue.class);
		assertEquals(signatureValue, unserialized);
	}

	@Test
	void testSerializationPolicy() throws Exception {
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
	void testSerializationBLevel() throws Exception {
		BLevelParameters blevel = new BLevelParameters();
		blevel.setSigningDate(new Date());
		List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
		commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
		blevel.setCommitmentTypeIndications(commitmentTypeIndications);

		byte[] serialized = serialize(blevel);
		BLevelParameters unserialized = unserialize(serialized, BLevelParameters.class);
		assertEquals(blevel, unserialized);
	}

	@Test
	void testSerializationSignerLocation() throws Exception {
		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setCountry("country");
		signerLocation.setLocality("locality");
		List<String> postalAddress = new ArrayList<>();
		postalAddress.add("Postal address");
		signerLocation.setPostalAddress(postalAddress);
		signerLocation.setPostalCode("postal code");
		signerLocation.setStateOrProvince("state");

		byte[] serialized = serialize(signerLocation);
		SignerLocation unserialized = unserialize(serialized, SignerLocation.class);
		assertEquals(signerLocation, unserialized);
	}

	@Test
	void testSerialization2() throws Exception {
		MockSignatureParameters testObj = new MockSignatureParameters();
		testObj.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		testObj.setSignaturePackaging(SignaturePackaging.DETACHED);
		testObj.setDigestAlgorithm(DigestAlgorithm.SHA1);
		testObj.bLevel().setSigningDate(new Date());
		List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
		commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
		testObj.bLevel().setCommitmentTypeIndications(commitmentTypeIndications);
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
		List<String> postalAddress = new ArrayList<>();
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
