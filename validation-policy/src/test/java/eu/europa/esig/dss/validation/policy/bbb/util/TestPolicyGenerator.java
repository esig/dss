package eu.europa.esig.dss.validation.policy.bbb.util;

import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.BasicSignatureConstraints;
import eu.europa.esig.jaxb.policy.CertificateConstraints;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.ListAlgo;
import eu.europa.esig.jaxb.policy.SignatureConstraints;
import eu.europa.esig.jaxb.policy.SignedAttributesConstraints;
import eu.europa.esig.jaxb.policy.UnsignedAttributesConstraints;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class TestPolicyGenerator {

	public static ValidationPolicy generatePolicy() {
		return generatePolicy(true);
	}

	public static ValidationPolicy generatePolicy(boolean policyMandatory) {

		ConstraintsParameters policy = new ConstraintsParameters();
		policy.setName("Test policy");

		SignatureConstraints constraints = new SignatureConstraints();

		TestMultiValueConstraint multi = new TestMultiValueConstraint();
		multi.setLevel(Level.FAIL);
		multi.addConstraint("ANY_POLICY");
		if (policyMandatory) {
			multi.addConstraint("NO_POLICY");
		}
		constraints.setAcceptablePolicies(multi);

		BasicSignatureConstraints basic = new BasicSignatureConstraints();
		basic.setCACertificate(generateCertConstraint());
		basic.setReferenceDataExistence(failLeveLConstraint());
		basic.setReferenceDataIntact(failLeveLConstraint());
		basic.setSignatureIntact(failLeveLConstraint());
		basic.setSignatureValid(failLeveLConstraint());
		basic.setSigningCertificate(generateCertConstraint());
		basic.setCryptographic(generateCryptographicConstrains());

		constraints.setBasicSignatureConstraints(basic);

		constraints.setStructuralValidation(failLeveLConstraint());

		SignedAttributesConstraints signedConstraints = new SignedAttributesConstraints();
		signedConstraints.setSignerLocation(infoLeveLConstraint());
		multi = new TestMultiValueConstraint();
		multi.setLevel(Level.INFORM);
		ValueConstraint vConstraint = new ValueConstraint();
		vConstraint.setValue("*");
		;
		vConstraint.setLevel(Level.INFORM);

		signedConstraints.setCertifiedRoles(multi);
		multi = new TestMultiValueConstraint();
		multi.setLevel(Level.INFORM);
		signedConstraints.setClaimedRoles(multi);
		multi = new TestMultiValueConstraint();
		multi.setLevel(Level.INFORM);
		signedConstraints.setCommitmentTypeIndication(multi);
		signedConstraints.setContentTimeStamp(infoLeveLConstraint());
		signedConstraints.setSigningTime(warnLeveLConstraint());
		signedConstraints.setContentHints(vConstraint);
		vConstraint = new ValueConstraint();
		vConstraint.setValue("*");
		;
		vConstraint.setLevel(Level.INFORM);
		signedConstraints.setContentIdentifier(vConstraint);
		vConstraint = new ValueConstraint();
		vConstraint.setValue("*");
		;
		vConstraint.setLevel(Level.INFORM);
		signedConstraints.setContentType(vConstraint);
		signedConstraints.setSignerLocation(infoLeveLConstraint());

		constraints.setSignedAttributes(signedConstraints);

		UnsignedAttributesConstraints unsignedConstraints = new UnsignedAttributesConstraints();
		unsignedConstraints.setCounterSignature(infoLeveLConstraint());

		constraints.setUnsignedAttributes(unsignedConstraints);

		policy.setSignatureConstraints(constraints);

		return new EtsiValidationPolicy(policy);
	}

	private static CertificateConstraints generateCertConstraint() {
		TestMultiValueConstraint keyUsage = new TestMultiValueConstraint();
		keyUsage.setLevel(Level.WARN);
		keyUsage.addConstraint("nonRepudiation");

		CertificateConstraints certConstraint = new CertificateConstraints();
		certConstraint.setKeyUsage(keyUsage);
		certConstraint.setAttributePresent(failLeveLConstraint());
		certConstraint.setCryptographic(generateCryptographicConstrains());
		certConstraint.setDigestValueMatch(failLeveLConstraint());
		certConstraint.setDigestValuePresent(failLeveLConstraint());
		certConstraint.setExpiration(failLeveLConstraint());
		certConstraint.setIssuerSerialMatch(failLeveLConstraint());
		certConstraint.setIssuedToLegalPerson(infoLeveLConstraint());
		certConstraint.setOnHold(failLeveLConstraint());
		certConstraint.setProspectiveCertificateChain(failLeveLConstraint());
		certConstraint.setQualification(warnLeveLConstraint());
		certConstraint.setRecognition(failLeveLConstraint());
		certConstraint.setRevocationDataAvailable(failLeveLConstraint());
		certConstraint.setRevocationDataIsTrusted(failLeveLConstraint());
		certConstraint.setRevocationDataFreshness(warnLeveLConstraint());
		certConstraint.setRevoked(failLeveLConstraint());
		certConstraint.setSignature(failLeveLConstraint());
		certConstraint.setSigned(failLeveLConstraint());
		certConstraint.setTSLStatusAndValidity(failLeveLConstraint());
		certConstraint.setTSLStatus(warnLeveLConstraint());
		certConstraint.setTSLValidity(warnLeveLConstraint());
		certConstraint.setSupportedBySSCD(warnLeveLConstraint());

		return certConstraint;
	}

	private static CryptographicConstraint generateCryptographicConstrains() {
		CryptographicConstraint result = new CryptographicConstraint();
		ListAlgo list = new ListAlgo();
		Algo algo = new Algo();
		algo.setValue("DSA");
		algo.setSize("128");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("RSA");
		algo.setSize("1024");
		list.getAlgo().add(algo);
		result.setAcceptableEncryptionAlgo(list);

		list = new ListAlgo();
		algo = new Algo();
		algo.setValue("SHA1");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("SHA224");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("SHA256");
		list.getAlgo().add(algo);
		algo = new Algo();
		algo.setValue("SHA384");
		list.getAlgo().add(algo);
		result.setAcceptableDigestAlgo(list);

		result.setLevel(Level.FAIL);

		return result;
	}

	private static LevelConstraint failLeveLConstraint() {
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		return failLevel;
	}

	private static LevelConstraint warnLeveLConstraint() {
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.WARN);
		return failLevel;
	}

	private static LevelConstraint infoLeveLConstraint() {
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.INFORM);
		return failLevel;
	}
}
